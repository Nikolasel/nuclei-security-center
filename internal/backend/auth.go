package backend

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// AuthConfig configures the backend as a confidential OIDC client (the BFF).
type AuthConfig struct {
	Issuer       string // OIDC issuer URL (discovery base)
	ClientID     string
	ClientSecret string
	// DiscoveryURL, if set, is the internal URL the backend fetches OIDC metadata
	// from, while Issuer stays the canonical (browser-facing) issuer. Needed when
	// the IdP is reachable at different hostnames from the browser and the backend
	// (e.g. Keycloak in Docker: localhost:8082 for the browser, keycloak:8080 for
	// the backend). Leave empty when both use the same URL.
	DiscoveryURL string
	RedirectURL  string            // this backend's /auth/callback URL, registered with the IdP
	PostLogin    string            // where to send the browser after a successful login
	PublicOrigin string            // public browser-facing app URL used for CSRF origin checks
	Scopes       []string          // OIDC scopes to request (must include openid)
	RolesClaim   string            // ID-token claim holding the user's groups/roles (e.g. "groups")
	GroupRoles   map[string]string // IdP group value -> local role
	SessionTTL   time.Duration
	CookieName   string
	SecureCookie bool // set the Secure flag (true behind TLS; false for local http)
	// LoginRate, LoginBurst, and LoginMaxClients tune unauthenticated login
	// admission. Zero selects the built-in safe default for each field.
	LoginRate       float64
	LoginBurst      int
	LoginMaxClients int
	// TrustedProxyCIDRs enables X-Forwarded-For parsing only when the direct
	// peer belongs to one of these explicitly trusted proxy networks. Empty
	// keeps the safe RemoteAddr-only behavior.
	TrustedProxyCIDRs []netip.Prefix
}

const (
	defaultSessionCookieName    = "nsc_session"
	hostCookiePrefix            = "__Host-"
	defaultAuthStateCookieName  = "nsc_auth_state"
	insecureAuthStateCookiePath = "/api/auth"
)

// Session TTL bounds (#189): an unbounded SESSION_TTL keeps a revoked admin
// authorized for the whole configured duration. The default is 12h; the
// maximum bounds the worst-case privilege-revocation window to a documented
// value. Deployments needing longer-lived sessions must re-authenticate.
const (
	DefaultSessionTTL = 12 * time.Hour
	MinSessionTTL     = 15 * time.Minute
	MaxSessionTTL     = 24 * time.Hour
)

// sessionCookieName returns the effective browser-session cookie name. Secure
// deployments use the __Host- prefix, which requires Secure, Path=/, and no
// Domain attribute and therefore prevents sibling subdomains from tossing a
// cookie for this host. Local plaintext development keeps the unprefixed name
// because browsers reject __Host- cookies without Secure.
func sessionCookieName(configured string, secure bool) string {
	name := strings.TrimSpace(configured)
	if name == "" {
		name = defaultSessionCookieName
	}
	if secure && !strings.HasPrefix(name, hostCookiePrefix) {
		name = hostCookiePrefix + name
	}
	return name
}

// authStateCookieName returns the effective OIDC state cookie name. Secure
// deployments use the __Host- prefix, which requires Secure, Path=/, and no
// Domain attribute and therefore prevents a sibling subdomain from fixing the
// login flow in the victim browser (login CSRF via cookie tossing).
// Local plaintext development keeps the unprefixed name because browsers
// reject __Host- cookies without Secure.
func authStateCookieName(secure bool) string {
	if secure {
		return hostCookiePrefix + defaultAuthStateCookieName
	}
	return defaultAuthStateCookieName
}

// authStateCookiePath returns the effective OIDC state cookie path.
// __Host- cookies require Path=/; the insecure fallback is scoped to
// /api/auth which still covers /api/auth/callback but limits exposure.
func authStateCookiePath(secure bool) string {
	if secure {
		return "/"
	}
	return insecureAuthStateCookiePath
}

// authStore is the subset of store.Store used by the authenticator. It exists
// so fault-injection tests can replace the real Postgres store with a fake that
// fails DeleteSession without needing a live database (#268).
//
// DeleteSession on this interface must remain idempotent (nil on missing row);
// see the extended comment on Store.DeleteSession — logout depends on it.
type authStore interface {
	CreateAuthFlow(ctx context.Context, f store.AuthFlow) error
	TakeAuthFlow(ctx context.Context, state string) (store.AuthFlow, error)
	UpsertUser(ctx context.Context, id store.Identity) error
	CreateSession(ctx context.Context, sess store.Session) error
	GetSession(ctx context.Context, id string) (store.Session, error)
	DeleteSession(ctx context.Context, id string) error
}

// Authenticator runs the OIDC authorization-code + BFF session flow.
type Authenticator struct {
	// store is intentionally interface-typed for fault injection. It must be
	// either a true nil interface (auth disabled / zero-value Authenticator in
	// tests) or a genuine non-nil store value. Assigning a typed nil
	// *store.Store would create a non-nil interface whose a.store != nil guard
	// passes but whose method call panics (nil-pointer dereference) instead of
	// taking the intended no-op path in handleLogout/Redirect/identityFromRequest.
	store    authStore
	log      *slog.Logger
	cfg      AuthConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config

	endSessionEndpoint string

	loginAdmissionOnce sync.Once
	loginAdmission     *loginAdmission
	trustedProxies     trustedProxySet
}

// NewAuthenticator performs OIDC discovery against the issuer and returns a
// ready authenticator. It fails fast if the IdP is unreachable or misconfigured.
func NewAuthenticator(ctx context.Context, st *store.Store, log *slog.Logger, cfg AuthConfig) (*Authenticator, error) {
	if err := validateLoginAdmissionConfig(cfg); err != nil {
		return nil, err
	}
	cfg.CookieName = sessionCookieName(cfg.CookieName, cfg.SecureCookie)
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.SessionTTL < MinSessionTTL || cfg.SessionTTL > MaxSessionTTL {
		return nil, fmt.Errorf("SESSION_TTL must be between %s and %s (got %s)", MinSessionTTL, MaxSessionTTL, cfg.SessionTTL)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "groups"
	}
	trustedProxies := newTrustedProxySet(cfg.TrustedProxyCIDRs)
	discoverFrom := cfg.Issuer
	if cfg.DiscoveryURL != "" {
		// Fetch metadata from the internal URL but trust cfg.Issuer as the issuer
		// that tokens are validated against.
		ctx = oidc.InsecureIssuerURLContext(ctx, cfg.Issuer)
		discoverFrom = cfg.DiscoveryURL
	}
	provider, err := oidc.NewProvider(ctx, discoverFrom)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	endSession := discoverEndSessionEndpoint(provider)
	if endSession != "" && log != nil {
		log.Info("oidc end_session_endpoint discovered", "endpoint", endSession)
	}
	return &Authenticator{
		store:              st,
		log:                log,
		cfg:                cfg,
		provider:           provider,
		verifier:           provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		endSessionEndpoint: endSession,
		trustedProxies:     trustedProxies,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
	}, nil
}

// providerEndSessionClaims is the minimal OIDC discovery document subset we
// need to locate the RP-initiated logout endpoint. The spec defines
// end_session_endpoint as OPTIONAL; a missing field means the IdP does not
// advertise RP-initiated logout and local-only logout is the correct fallback.
type providerEndSessionClaims struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
}

func discoverEndSessionEndpoint(p *oidc.Provider) string {
	if p == nil {
		return ""
	}
	var c providerEndSessionClaims
	if err := p.Claims(&c); err != nil {
		return ""
	}
	return strings.TrimSpace(c.EndSessionEndpoint)
}

// endSessionURL builds the RP-initiated logout URL for the browser to visit
// after the local NSC session has been cleared. It appends client_id and
// post_logout_redirect_uri so the IdP can validate the return and terminate
// its own SSO cookie. The IdP session is the reason a shared-workstation
// attacker could otherwise re-mint an NSC session with one click after the
// victim's local logout — this URL drives the IdP to clear it. When the
// provider does not advertise an end_session_endpoint the caller must fall
// back to local-only logout.
func (a *Authenticator) endSessionURL() string {
	ep := strings.TrimSpace(a.endSessionEndpoint)
	if ep == "" {
		return ""
	}
	u, err := url.Parse(ep)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	// Restrict to HTTP(S) so a compromised or misconfigured discovery document
	// cannot inject javascript:, data:, or other schemes that would reach
	// window.location.assign on the SPA.
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	q := u.Query()
	q.Set("client_id", a.cfg.ClientID)
	// post_logout_redirect_uri must be an absolute URL whitelisted at the IdP.
	// Prefer the configured public origin; fall back to PostLogin when it is
	// itself an absolute URL. Relative values are resolved against PublicOrigin.
	redirect := strings.TrimSpace(a.cfg.PostLogin)
	if redirect == "" || (!strings.HasPrefix(redirect, "http://") && !strings.HasPrefix(redirect, "https://")) {
		base := strings.TrimSpace(a.cfg.PublicOrigin)
		if base == "" {
			base = "http://localhost:8080"
		}
		if redirect == "" || redirect == "/" {
			redirect = strings.TrimSuffix(base, "/") + "/"
		} else if strings.HasPrefix(redirect, "/") {
			redirect = strings.TrimSuffix(base, "/") + redirect
		} else {
			redirect = strings.TrimSuffix(base, "/") + "/" + redirect
		}
	}
	q.Set("post_logout_redirect_uri", redirect)
	u.RawQuery = q.Encode()
	return u.String()
}

const (
	authFlowTTL           = 10 * time.Minute
	authStateCookieMaxAge = int(authFlowTTL / time.Second)
)

// handleLogin begins the authorization-code flow: it mints CSRF state, a nonce,
// and a PKCE verifier, stashes them server-side, and redirects to the IdP.
func (a *Authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !a.loginAdmitter().allow(authLoginClientKey(r, a.trustedProxies)) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	state := randToken()
	nonce := randToken()
	verifier := oauth2.GenerateVerifier()

	flow := store.AuthFlow{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     authReturnTo(r.URL.Query().Get("return_to")),
		ExpiresAt:    time.Now().Add(authFlowTTL),
	}
	if err := a.store.CreateAuthFlow(r.Context(), flow); err != nil {
		if errors.Is(err, store.ErrAuthFlowBusy) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "login temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if errors.Is(err, store.ErrAuthFlowLimit) {
			http.Error(w, "login temporarily unavailable", http.StatusTooManyRequests)
			return
		}
		a.log.Error("create auth flow", "err", err)
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	a.setAuthStateCookie(w, state)

	url := a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback completes the flow: it validates state, exchanges the code
// (with PKCE), verifies the ID token + nonce, maps roles, and establishes a
// server-side session delivered as an httpOnly cookie.
func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	state := r.URL.Query().Get("state")
	if !a.authStateMatches(r, state) {
		http.Error(w, "invalid or expired login state", http.StatusBadRequest)
		return
	}
	// Clear before any response write so the deletion reaches the browser.
	a.clearAuthStateCookie(w)

	if e := r.URL.Query().Get("error"); e != "" {
		a.recordCallbackFailure(r, start)
		http.Error(w, "identity provider error: "+e, http.StatusUnauthorized)
		return
	}
	flow, err := a.store.TakeAuthFlow(r.Context(), state)
	if err != nil {
		// Unknown/expired/replayed state — also the CSRF guard.
		http.Error(w, "invalid or expired login state", http.StatusBadRequest)
		return
	}

	token, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"),
		oauth2.VerifierOption(flow.PKCEVerifier))
	if err != nil {
		a.log.Warn("code exchange failed", "err", err)
		a.recordCallbackFailure(r, start)
		http.Error(w, "code exchange failed", http.StatusUnauthorized)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}
	idToken, err := a.verifier.Verify(r.Context(), rawID)
	if err != nil {
		a.log.Warn("id token verify failed", "err", err)
		a.recordCallbackFailure(r, start)
		http.Error(w, "invalid id token", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != flow.Nonce {
		a.recordCallbackFailure(r, start)
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "cannot parse claims", http.StatusInternalServerError)
		return
	}
	id := store.Identity{
		Subject: idToken.Subject,
		Email:   claimString(claims, "email"),
		Name:    firstNonEmpty(claimString(claims, "name"), claimString(claims, "preferred_username")),
		Roles:   a.mapRoles(claims),
	}
	if err := a.store.UpsertUser(r.Context(), id); err != nil {
		a.log.Error("upsert user", "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	sess := store.Session{ID: randToken(), Identity: id, ExpiresAt: time.Now().Add(a.cfg.SessionTTL)}
	if err := a.store.CreateSession(r.Context(), sess); err != nil {
		a.log.Error("create session", "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	a.setSessionCookie(w, sess.ID, sess.ExpiresAt)

	dest := firstNonEmpty(safeReturnTo(flow.ReturnTo), a.cfg.PostLogin, "/")
	http.Redirect(w, r, dest, http.StatusFound)
}

// recordCallbackFailure emits a structured authentication-denial audit event for
// the public OIDC callback. The callback is registered outside requireAuth
// (internal/backend/http.go), so its 401s are not covered by the shared
// middleware; each IdP error, code-exchange failure, token-verification failure,
// and nonce failure must emit the same event_id=access_denied trail as the
// protected routes. auth_method is a bounded, non-secret value and no query
// values (code, state, error, nonce) are logged, mirroring
// Server.recordAuthenticationFailure.
func (a *Authenticator) recordCallbackFailure(r *http.Request, start time.Time) {
	if a.log == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("event", "audit"),
		slog.String("event_id", eventAccessDenied),
		slog.String("action", "auth.authenticate"),
		slog.String("actor_subject", "unknown"),
		slog.String("actor_type", "unknown"),
		slog.String("auth_method", "oidc_callback"),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", http.StatusUnauthorized),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
	}
	a.log.LogAttrs(r.Context(), slog.LevelInfo, "audit auth.authenticate", attrs...)
}

// handleLogout clears the server-side session and the cookie and, when the
// provider advertises an end_session_endpoint, returns the RP-initiated logout
// URL for the SPA to follow. Local session deletion is always performed;
// the IdP redirect is an additional step to clear the IdP's SSO cookie so a
// subsequent visit to /api/auth/login does not silently re-mint a session
// from the still-live IdP session (CWE-613 — shared-workstation reuse).
// When no end_session_endpoint is advertised the response is 204 and the
// caller falls back to a local-only logout (the correct behavior for IdPs
// that do not support RP-initiated logout).
//
// If server-side revocation fails (e.g. a transient Postgres outage) the
// handler fails closed: it returns 503 with Retry-After and preserves the
// browser cookie so the caller can retry. A response presented as successful
// logout therefore always means the session row is gone, so a copied cookie
// cannot be replayed after the user saw success (#268).
func (a *Authenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	if a.store != nil {
		if c, err := r.Cookie(a.sessionCookieName()); err == nil && c.Value != "" {
			if err := a.store.DeleteSession(r.Context(), c.Value); err != nil {
				if a.log != nil {
					a.log.Error("delete session", "err", err)
				}
				w.Header().Set("Retry-After", "1")
				http.Error(w, "logout temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}
	}
	a.clearSessionCookie(w)
	if dest := a.endSessionURL(); dest != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"end_session_url": dest})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleLogoutRedirect is the GET counterpart for browser-initiated navigations.
// It clears the local session and then redirects the top-level browser to the
// IdP's end_session_endpoint when known, otherwise to "/" — so a user who
// navigates to /api/auth/logout directly still terminates both sessions.
//
// Like handleLogout it fails closed on revocation errors: a 503 with
// Retry-After, no cookie clearing and no redirect, so a transient store
// failure cannot be mistaken for a successful logout (#268).
func (a *Authenticator) handleLogoutRedirect(w http.ResponseWriter, r *http.Request) {
	if a.store != nil {
		if c, err := r.Cookie(a.sessionCookieName()); err == nil && c.Value != "" {
			if err := a.store.DeleteSession(r.Context(), c.Value); err != nil {
				if a.log != nil {
					a.log.Error("delete session", "err", err)
				}
				w.Header().Set("Retry-After", "1")
				http.Error(w, "logout temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}
	}
	a.clearSessionCookie(w)
	if dest := a.endSessionURL(); dest != "" {
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// identityFromRequest resolves the session cookie to a live identity.
//
// The second return value is the session-lookup error if the underlying store
// call failed for a reason other than the session not existing (#82): during
// a Postgres outage, connection rotation, or other infrastructure fault, a
// caller must not be told their session is invalid (a 401) — they should see
// a retryable server error (a 503) so the SPA doesn't bounce them through a
// pointless re-login that fails at the same lookup. A missing/empty cookie or
// ErrNotFound still returns (zero, nil) so the middleware emits a 401.
func (a *Authenticator) identityFromRequest(r *http.Request) (store.Identity, error) {
	c, err := r.Cookie(a.sessionCookieName())
	if err != nil || c.Value == "" {
		return store.Identity{}, nil
	}
	if a.store == nil {
		return store.Identity{}, nil
	}
	sess, err := a.store.GetSession(r.Context(), c.Value)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			a.log.Error("get session", "err", err)
			return store.Identity{}, err
		}
		return store.Identity{}, nil
	}
	return sess.Identity, nil
}

// mapRoles turns the configured groups/roles claim into local roles.
func (a *Authenticator) mapRoles(claims map[string]any) []string {
	seen := map[string]bool{}
	var roles []string
	for _, g := range claimStrings(claims, a.cfg.RolesClaim) {
		role, ok := a.cfg.GroupRoles[g]
		if !ok || seen[role] {
			continue
		}
		seen[role] = true
		roles = append(roles, role)
	}
	return roles
}

func (a *Authenticator) setSessionCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookieName(),
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func authStateMatches(r *http.Request, state string, secure bool) bool {
	if state == "" {
		return false
	}
	c, err := r.Cookie(authStateCookieName(secure))
	return err == nil && c.Value != "" && c.Value == state
}

func (a *Authenticator) authStateMatches(r *http.Request, state string) bool {
	return authStateMatches(r, state, a.cfg.SecureCookie)
}

func (a *Authenticator) setAuthStateCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.authStateCookieName(),
		Value:    value,
		Path:     a.authStateCookiePath(),
		Expires:  time.Now().Add(authFlowTTL),
		MaxAge:   authStateCookieMaxAge,
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) clearAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.authStateCookieName(),
		Value:    "",
		Path:     a.authStateCookiePath(),
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) authStateCookieName() string {
	return authStateCookieName(a.cfg.SecureCookie)
}

func (a *Authenticator) authStateCookiePath() string {
	return authStateCookiePath(a.cfg.SecureCookie)
}

func (a *Authenticator) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) sessionCookieName() string {
	return sessionCookieName(a.cfg.CookieName, a.cfg.SecureCookie)
}

// randToken returns a 256-bit URL-safe random string for session/state/nonce use.
func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error()) // unreachable on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// safeReturnTo only allows relative, single-slash-rooted paths to prevent open
// redirects via the return_to parameter. It is deny-by-default: the value must
// start with a single '/' and must not be reinterpretable as a scheme-relative
// ("//host") or absolute URL. The backslash variant ("/\host") is rejected
// explicitly because WHATWG-URL browsers normalize '\' to '/', turning it into
// a scheme-relative //host redirect (CWE-601).
func safeReturnTo(p string) string {
	if len(p) < 2 || p[0] != '/' || p[1] == '/' || p[1] == '\\' {
		return ""
	}
	u, err := url.Parse(p)
	if err != nil || u.IsAbs() || u.Host != "" {
		return ""
	}
	return p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func claimString(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// claimStrings reads a claim that is either a JSON array of strings or a single
// string, returning it as a slice.
func claimStrings(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		return []string{v}
	default:
		return nil
	}
}
