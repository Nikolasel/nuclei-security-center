package backend

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	Scopes       []string          // OIDC scopes to request (must include openid)
	RolesClaim   string            // ID-token claim holding the user's groups/roles (e.g. "groups")
	GroupRoles   map[string]string // IdP group value -> local role
	SessionTTL   time.Duration
	CookieName   string
	SecureCookie bool // set the Secure flag (true behind TLS; false for local http)
}

// Authenticator runs the OIDC authorization-code + BFF session flow.
type Authenticator struct {
	store    *store.Store
	log      *slog.Logger
	cfg      AuthConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// NewAuthenticator performs OIDC discovery against the issuer and returns a
// ready authenticator. It fails fast if the IdP is unreachable or misconfigured.
func NewAuthenticator(ctx context.Context, st *store.Store, log *slog.Logger, cfg AuthConfig) (*Authenticator, error) {
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
	if cfg.CookieName == "" {
		cfg.CookieName = "nsc_session"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "groups"
	}
	return &Authenticator{
		store:    st,
		log:      log,
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
	}, nil
}

const authFlowTTL = 10 * time.Minute

// handleLogin begins the authorization-code flow: it mints CSRF state, a nonce,
// and a PKCE verifier, stashes them server-side, and redirects to the IdP.
func (a *Authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randToken()
	nonce := randToken()
	verifier := oauth2.GenerateVerifier()

	flow := store.AuthFlow{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     r.URL.Query().Get("return_to"),
		ExpiresAt:    time.Now().Add(authFlowTTL),
	}
	if err := a.store.CreateAuthFlow(r.Context(), flow); err != nil {
		a.log.Error("create auth flow", "err", err)
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}

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
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "identity provider error: "+e, http.StatusUnauthorized)
		return
	}
	flow, err := a.store.TakeAuthFlow(r.Context(), r.URL.Query().Get("state"))
	if err != nil {
		// Unknown/expired/replayed state — also the CSRF guard.
		http.Error(w, "invalid or expired login state", http.StatusBadRequest)
		return
	}

	token, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"),
		oauth2.VerifierOption(flow.PKCEVerifier))
	if err != nil {
		a.log.Warn("code exchange failed", "err", err)
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
		http.Error(w, "invalid id token", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != flow.Nonce {
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

// handleLogout clears the server-side session and the cookie.
func (a *Authenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(a.cfg.CookieName); err == nil {
		_ = a.store.DeleteSession(r.Context(), c.Value)
	}
	a.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// identityFromRequest resolves the session cookie to a live identity.
func (a *Authenticator) identityFromRequest(r *http.Request) (store.Identity, bool) {
	c, err := r.Cookie(a.cfg.CookieName)
	if err != nil || c.Value == "" {
		return store.Identity{}, false
	}
	sess, err := a.store.GetSession(r.Context(), c.Value)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			a.log.Error("get session", "err", err)
		}
		return store.Identity{}, false
	}
	return sess.Identity, true
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
		Name:     a.cfg.CookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
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
// redirects via the return_to parameter.
func safeReturnTo(p string) string {
	if len(p) >= 2 && p[0] == '/' && p[1] != '/' {
		return p
	}
	return ""
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
