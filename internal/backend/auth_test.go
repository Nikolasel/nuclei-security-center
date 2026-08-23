package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestSatisfies(t *testing.T) {
	cases := []struct {
		roles    []string
		required string
		want     bool
	}{
		{[]string{RoleAdmin}, RoleViewer, true},   // admin outranks viewer
		{[]string{RoleAdmin}, RoleOperator, true}, // admin outranks operator
		{[]string{RoleOperator}, RoleOperator, true},
		{[]string{RoleOperator}, RoleAdmin, false},  // operator can't delete
		{[]string{RoleViewer}, RoleOperator, false}, // viewer can't run scans
		{[]string{RoleViewer}, RoleViewer, true},
		{nil, RoleViewer, false},               // no roles -> denied
		{[]string{"bogus"}, RoleViewer, false}, // unknown role ranks 0
		{[]string{"bogus", RoleAdmin}, RoleAdmin, true},
	}
	for _, c := range cases {
		if got := satisfies(store.Identity{Roles: c.roles}, c.required); got != c.want {
			t.Errorf("satisfies(%v, %q) = %v, want %v", c.roles, c.required, got, c.want)
		}
	}
}

func TestMapRoles(t *testing.T) {
	a := &Authenticator{cfg: AuthConfig{
		RolesClaim: "groups",
		GroupRoles: map[string]string{
			"nsc-admin":    RoleAdmin,
			"nsc-operator": RoleOperator,
			"nsc-viewer":   RoleViewer,
		},
	}}

	// Array claim, mixed known/unknown, with a duplicate mapping target.
	got := a.mapRoles(map[string]any{
		"groups": []any{"nsc-operator", "unrelated", "nsc-viewer", "nsc-viewer"},
	})
	sort.Strings(got)
	want := []string{RoleOperator, RoleViewer}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mapRoles array = %v, want %v", got, want)
	}

	// Single string claim.
	if got := a.mapRoles(map[string]any{"groups": "nsc-admin"}); !reflect.DeepEqual(got, []string{RoleAdmin}) {
		t.Errorf("mapRoles string = %v, want [admin]", got)
	}

	// Missing claim -> no roles.
	if got := a.mapRoles(map[string]any{}); len(got) != 0 {
		t.Errorf("mapRoles missing = %v, want empty", got)
	}
}

func TestSafeReturnTo(t *testing.T) {
	ok := []string{"/dashboard", "/findings?scan_id=1"}
	for _, p := range ok {
		if safeReturnTo(p) != p {
			t.Errorf("safeReturnTo(%q) rejected a valid relative path", p)
		}
	}
	bad := []string{
		"", "//evil.com", "https://evil.com", "relative", "/",
		`/\evil.com`, `/\/evil.com`, `\/evil.com`, `\\evil.com`, `/\`,
	}
	for _, p := range bad {
		if safeReturnTo(p) != "" {
			t.Errorf("safeReturnTo(%q) = %q, want \"\" (open-redirect guard)", p, safeReturnTo(p))
		}
	}
}

func TestCallbackRejectsUnboundAuthStateBeforeStoreAccess(t *testing.T) {
	const state = "expected-state"
	cases := []struct {
		name        string
		cookieState string
	}{
		{name: "missing cookie"},
		{name: "mismatched cookie", cookieState: "other-state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state="+state, nil)
			if tc.cookieState != "" {
				req.AddCookie(&http.Cookie{Name: authStateCookieName(false), Value: tc.cookieState})
			}
			rr := httptest.NewRecorder()
			(&Authenticator{}).handleCallback(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			if got := rr.Header().Get("Set-Cookie"); got != "" {
				t.Fatalf("callback minted a cookie before state validation: %q", got)
			}
		})
	}
}

func TestCallbackClearsBoundAuthStateBeforeWritingResponse(t *testing.T) {
	const state = "expected-state"
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state="+state+"&error=access_denied", nil)
	req.AddCookie(&http.Cookie{Name: authStateCookieName(false), Value: state})
	rr := httptest.NewRecorder()
	(&Authenticator{}).handleCallback(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("client Set-Cookie count = %d, want 1", len(cookies))
	}
	if cookies[0].Name != authStateCookieName(false) || cookies[0].MaxAge != -1 || cookies[0].Path != authStateCookiePath(false) {
		t.Fatalf("client clear cookie = %#v, want expired auth-state cookie", cookies[0])
	}
}

func TestAuthStateCookieMatchesOnlyTheExpectedState(t *testing.T) {
	const state = "expected-state"
	cases := []struct {
		name        string
		cookieState string
		want        bool
	}{
		{name: "matching", cookieState: state, want: true},
		{name: "missing", want: false},
		{name: "mismatched", cookieState: "other-state", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state="+state, nil)
			if tc.cookieState != "" {
				req.AddCookie(&http.Cookie{Name: authStateCookieName(false), Value: tc.cookieState})
			}
			if got := authStateMatches(req, state, false); got != tc.want {
				t.Fatalf("authStateMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuthStateMatchesIsolatesSecureCookie(t *testing.T) {
	const state = "expected-state"
	legacyName := authStateCookieName(false)
	hostName := authStateCookieName(true)
	if legacyName == hostName {
		t.Fatalf("legacy and host cookie names must differ: %q", legacyName)
	}
	cases := []struct {
		name       string
		secure     bool
		cookieName string
		cookieVal  string
		want       bool
	}{
		{name: "secure accepts host cookie", secure: true, cookieName: hostName, cookieVal: state, want: true},
		{name: "secure rejects legacy cookie even with matching value", secure: true, cookieName: legacyName, cookieVal: state, want: false},
		{name: "secure rejects mismatched host cookie", secure: true, cookieName: hostName, cookieVal: "other-state", want: false},
		{name: "insecure accepts legacy cookie", secure: false, cookieName: legacyName, cookieVal: state, want: true},
		{name: "insecure rejects host cookie even with matching value", secure: false, cookieName: hostName, cookieVal: state, want: false},
		{name: "missing cookie always false", secure: true, cookieName: "", cookieVal: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state="+state, nil)
			if tc.cookieName != "" {
				req.AddCookie(&http.Cookie{Name: tc.cookieName, Value: tc.cookieVal})
			}
			if got := authStateMatches(req, state, tc.secure); got != tc.want {
				t.Fatalf("authStateMatches(secure=%v, cookie %q=%q) = %v, want %v", tc.secure, tc.cookieName, tc.cookieVal, got, tc.want)
			}
		})
	}

	// HandleCallback in secure mode must also reject a legacy cookie before store access.
	t.Run("secure handleCallback rejects legacy cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state="+state, nil)
		req.AddCookie(&http.Cookie{Name: legacyName, Value: state})
		rr := httptest.NewRecorder()
		(&Authenticator{cfg: AuthConfig{SecureCookie: true}}).handleCallback(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
		if got := rr.Header().Get("Set-Cookie"); got != "" {
			t.Fatalf("callback minted a cookie before state validation: %q", got)
		}
	})
}

func TestAuthStateCookiePathCoversCallbackRoute(t *testing.T) {
	const callbackPath = "/api/auth/callback"
	for _, secure := range []bool{false, true} {
		path := authStateCookiePath(secure)
		cookiePath := strings.TrimSuffix(path, "/")
		// "/" covers every path; the check below would otherwise require "/"+...
		// Special-case the host-locked "/" which is the __Host- requirement.
		if path == "/" {
			continue
		}
		if path == "" || !strings.HasPrefix(callbackPath, cookiePath+"/") {
			t.Fatalf("auth-state cookie path %q (secure=%v) does not cover callback route %q", path, secure, callbackPath)
		}
	}
	// Explicitly verify the host-locked secure path is "/" as required by __Host-.
	if got := authStateCookiePath(true); got != "/" {
		t.Fatalf("secure auth-state cookie path = %q, want \"/\"", got)
	}
}

func TestAuthStateCookieAttributes(t *testing.T) {
	a := &Authenticator{cfg: AuthConfig{SecureCookie: true}}
	rr := httptest.NewRecorder()
	a.setAuthStateCookie(rr, "expected-state")
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	wantName := authStateCookieName(true)
	wantPath := authStateCookiePath(true)
	if cookie.Name != wantName || cookie.Value != "expected-state" {
		t.Fatalf("cookie identity = %q=%q, want %q=%q", cookie.Name, cookie.Value, wantName, "expected-state")
	}
	if cookie.Path != wantPath || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" {
		t.Fatalf("cookie attributes = path %q domain %q, HttpOnly %v, Secure %v, SameSite %v", cookie.Path, cookie.Domain, cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}
	if cookie.MaxAge <= 0 || !cookie.Expires.After(time.Now()) {
		t.Fatalf("cookie lifetime = max-age %d, expires %v", cookie.MaxAge, cookie.Expires)
	}

	clear := httptest.NewRecorder()
	a.clearAuthStateCookie(clear)
	cleared := clear.Result().Cookies()
	if len(cleared) != 1 {
		t.Fatalf("clear Set-Cookie count = %d, want 1", len(cleared))
	}
	if cleared[0].Name != wantName || cleared[0].Path != wantPath || cleared[0].MaxAge != -1 || !cleared[0].HttpOnly || !cleared[0].Secure || cleared[0].SameSite != http.SameSiteLaxMode || cleared[0].Domain != "" {
		t.Fatalf("clear cookie = %#v, want matching expired host-locked cookie", cleared[0])
	}
}

func TestAuthStateCookieAttributesInsecure(t *testing.T) {
	a := &Authenticator{cfg: AuthConfig{SecureCookie: false}}
	rr := httptest.NewRecorder()
	a.setAuthStateCookie(rr, "expected-state")
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	wantName := authStateCookieName(false)
	wantPath := authStateCookiePath(false)
	if cookie.Name != wantName || cookie.Value != "expected-state" {
		t.Fatalf("cookie identity = %q=%q, want %q=%q", cookie.Name, cookie.Value, wantName, "expected-state")
	}
	if cookie.Path != wantPath || !cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" {
		t.Fatalf("insecure cookie attributes = path %q domain %q, HttpOnly %v, Secure %v, SameSite %v", cookie.Path, cookie.Domain, cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}

	clear := httptest.NewRecorder()
	a.clearAuthStateCookie(clear)
	cleared := clear.Result().Cookies()
	if len(cleared) != 1 {
		t.Fatalf("clear Set-Cookie count = %d, want 1", len(cleared))
	}
	if cleared[0].Name != wantName || cleared[0].Path != wantPath || cleared[0].MaxAge != -1 {
		t.Fatalf("clear cookie = %#v, want matching expired insecure cookie", cleared[0])
	}
}

func TestAuthStateCookieUsesHostPrefixWhenSecure(t *testing.T) {
	secureName := authStateCookieName(true)
	securePath := authStateCookiePath(true)
	if secureName != "__Host-nsc_auth_state" {
		t.Fatalf("secure auth-state cookie name = %q, want __Host-nsc_auth_state", secureName)
	}
	if securePath != "/" {
		t.Fatalf("secure auth-state cookie path = %q, want /", securePath)
	}
	insecureName := authStateCookieName(false)
	insecurePath := authStateCookiePath(false)
	if insecureName != "nsc_auth_state" {
		t.Fatalf("insecure auth-state cookie name = %q, want nsc_auth_state", insecureName)
	}
	if insecurePath != "/api/auth" {
		t.Fatalf("insecure auth-state cookie path = %q, want /api/auth", insecurePath)
	}
}

func TestSessionCookieUsesHostPrefixWhenSecure(t *testing.T) {
	a := &Authenticator{cfg: AuthConfig{
		CookieName:   "nsc_session",
		SecureCookie: true,
	}}
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, "session-token", time.Now().Add(time.Hour))

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-nsc_session" {
		t.Fatalf("session cookie name = %q, want __Host-nsc_session", cookie.Name)
	}
	if cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie attributes = %#v, want Secure HttpOnly SameSite=Lax Path=/ without Domain", cookie)
	}

	clear := httptest.NewRecorder()
	a.clearSessionCookie(clear)
	cleared := clear.Result().Cookies()
	if len(cleared) != 1 {
		t.Fatalf("clear Set-Cookie count = %d, want 1", len(cleared))
	}
	if cleared[0].Name != cookie.Name || cleared[0].Path != "/" || cleared[0].Domain != "" || cleared[0].MaxAge != -1 || !cleared[0].Secure {
		t.Fatalf("cleared session cookie = %#v, want matching host-only cookie", cleared[0])
	}
}

func TestSessionCookieKeepsLocalDevelopmentNameWithoutSecure(t *testing.T) {
	a := &Authenticator{cfg: AuthConfig{SecureCookie: false}}
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, "session-token", time.Now().Add(time.Hour))

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1", len(cookies))
	}
	if cookies[0].Name != "nsc_session" || cookies[0].Secure {
		t.Fatalf("local session cookie = %#v, want nsc_session without Secure", cookies[0])
	}
}

func TestHandleLoginBindsCookieToRedirectStatePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)
	a := &Authenticator{
		store: st,
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg: AuthConfig{
			SecureCookie: true,
		},
		oauth: &oauth2.Config{
			ClientID:    "test-client",
			RedirectURL: "https://app.test/api/auth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://idp.test/authorize",
				TokenURL: "https://idp.test/token",
			},
			Scopes: []string{"openid"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/login?return_to=/dashboard", nil)
	rr := httptest.NewRecorder()
	a.handleLogin(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want %d", rr.Code, http.StatusFound)
	}
	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP redirect: %v", err)
	}
	state := location.Query().Get("state")
	if state == "" {
		t.Fatal("IdP redirect did not contain state")
	}

	var stateCookie *http.Cookie
	wantCookieName := authStateCookieName(true)
	wantCookiePath := authStateCookiePath(true)
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == wantCookieName {
			stateCookie = cookie
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("login did not set the browser-bound auth-state cookie")
	}
	if stateCookie.Value != state {
		t.Fatalf("auth-state cookie = %q, redirect state = %q", stateCookie.Value, state)
	}
	if stateCookie.Path != wantCookiePath || !stateCookie.HttpOnly || !stateCookie.Secure || stateCookie.SameSite != http.SameSiteLaxMode || stateCookie.Domain != "" {
		t.Fatalf("login auth-state cookie attributes = %#v, want host-locked Secure HttpOnly SameSite=Lax Path=/", stateCookie)
	}

	flow, err := st.TakeAuthFlow(ctx, state)
	if err != nil {
		t.Fatalf("stored auth flow = %v", err)
	}
	if flow.ReturnTo != "/dashboard" || flow.Nonce == "" || flow.PKCEVerifier == "" {
		t.Fatalf("stored auth flow = %+v", flow)
	}
}

func TestCallbackIdPErrorEmitsAccessDeniedAudit(t *testing.T) {
	var buf bytes.Buffer
	a := &Authenticator{log: slog.New(slog.NewJSONHandler(&buf, nil))}
	const state = "expected-state"
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state="+state+"&error=access_denied&error_description=evil", nil)
	req.AddCookie(&http.Cookie{Name: authStateCookieName(false), Value: state})
	rr := httptest.NewRecorder()
	a.handleCallback(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	ev := lastAuditFromBuf(t, &buf)
	for k, want := range map[string]any{
		"event":         "audit",
		"event_id":      eventAccessDenied,
		"action":        "auth.authenticate",
		"actor_subject": "unknown",
		"actor_type":    "unknown",
		"auth_method":   "oidc_callback",
		"method":        http.MethodGet,
		"path":          "/api/auth/callback",
		"status":        float64(http.StatusUnauthorized),
	} {
		if ev[k] != want {
			t.Errorf("audit %q = %v, want %v", k, ev[k], want)
		}
	}
	if _, ok := ev["duration_ms"]; !ok {
		t.Error("duration_ms missing")
	}
	raw := buf.String()
	if strings.Contains(raw, "evil") {
		t.Errorf("audit log leaked IdP error description: %s", raw)
	}
	if strings.Contains(raw, state) {
		t.Errorf("audit log leaked state: %s", raw)
	}
	if cookies := rr.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge != -1 {
		t.Fatalf("cookie not cleared: %v", cookies)
	}
}

func TestCallbackRecordFailureDoesNotLeakSecrets(t *testing.T) {
	var buf bytes.Buffer
	a := &Authenticator{log: slog.New(slog.NewJSONHandler(&buf, nil))}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state=secret-state&code=secret-code&error=evil", nil)
	a.recordCallbackFailure(req, time.Now().Add(-5*time.Millisecond))
	raw := buf.String()
	if strings.Contains(raw, "secret-state") || strings.Contains(raw, "secret-code") || strings.Contains(raw, "evil") {
		t.Fatalf("audit leaked secret query values: %s", raw)
	}
	ev := lastAuditFromBuf(t, &buf)
	if ev["auth_method"] != "oidc_callback" {
		t.Errorf("auth_method = %v, want oidc_callback", ev["auth_method"])
	}
	if ev["event_id"] != eventAccessDenied {
		t.Errorf("event_id = %v, want %v", ev["event_id"], eventAccessDenied)
	}
}

// TestRecordCallbackFailureEnvelope pins the shared audit helper's envelope: every
// logical callback 401 branch (IdP error, code exchange, ID-token verification,
// nonce mismatch) must emit the same bounded event with no secret query values.
// This is a helper-level contract test; handler-level wiring for the IdP-error
// and code-exchange branches is covered by TestCallbackIdPErrorEmitsAccessDeniedAudit
// and TestCallbackCodeExchangeEmitsAccessDeniedAudit respectively, while the
// verifier and nonce branches (which would require a full OIDC/JWT fixture per row)
// are covered here at the helper level.
func TestRecordCallbackFailureEnvelope(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{name: "idp_error", method: http.MethodGet, path: "/api/auth/callback"},
		{name: "code_exchange", method: http.MethodGet, path: "/api/auth/callback"},
		{name: "id_token_verify", method: http.MethodGet, path: "/api/auth/callback"},
		{name: "nonce_mismatch", method: http.MethodGet, path: "/api/auth/callback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			a := &Authenticator{log: slog.New(slog.NewJSONHandler(&buf, nil))}
			// Every branch must not log the request's secrets - use a request
			// that carries all of them so a leaking format would be caught.
			req := httptest.NewRequest(tc.method, tc.path+"?state=secret-state&code=secret-code&error=evil", nil)
			a.recordCallbackFailure(req, time.Now().Add(-2*time.Millisecond))
			raw := buf.String()
			if strings.Contains(raw, "secret-state") || strings.Contains(raw, "secret-code") || strings.Contains(raw, "evil") {
				t.Fatalf("%s: audit leaked secret query values: %s", tc.name, raw)
			}
			ev := lastAuditFromBuf(t, &buf)
			for k, want := range map[string]any{
				"event":         "audit",
				"event_id":      eventAccessDenied,
				"action":        "auth.authenticate",
				"actor_subject": "unknown",
				"actor_type":    "unknown",
				"auth_method":   "oidc_callback",
				"method":        tc.method,
				"path":          tc.path,
				"status":        float64(http.StatusUnauthorized),
			} {
				if ev[k] != want {
					t.Errorf("%s: audit %q = %v, want %v", tc.name, k, ev[k], want)
				}
			}
			if _, ok := ev["duration_ms"]; !ok {
				t.Errorf("%s: duration_ms missing", tc.name)
			}
		})
	}
}

// TestCallbackCodeExchangeEmitsAccessDeniedAudit exercises a second 401 branch
// end-to-end: a stored auth flow with a failing token endpoint. This proves the
// wiring from handleCallback's Exchange error through the shared audit helper
// without requiring a full JWT fixture for the verifier/nonce branches.
func TestCallbackCodeExchangeEmitsAccessDeniedAudit(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "exchange failed", http.StatusInternalServerError)
	}))
	defer tokenSrv.Close()

	var buf bytes.Buffer
	a := &Authenticator{
		store: st,
		log:   slog.New(slog.NewJSONHandler(&buf, nil)),
		oauth: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://app.test/api/auth/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenSrv.URL,
			},
		},
		// Verifier is not reached on exchange failure, but set a dummy to avoid nil panic if wiring changes.
		verifier: nil,
	}

	flow := store.AuthFlow{
		State:        "exchange-state-" + time.Now().Format("150405.000"),
		Nonce:        "test-nonce",
		PKCEVerifier: "test-verifier",
		ReturnTo:     "/",
		ExpiresAt:    time.Now().Add(authFlowTTL),
	}
	if err := st.CreateAuthFlow(ctx, flow); err != nil {
		t.Fatalf("create auth flow: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state="+flow.State+"&code=secret-code", nil)
	req.AddCookie(&http.Cookie{Name: authStateCookieName(false), Value: flow.State})
	rr := httptest.NewRecorder()
	a.handleCallback(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	ev := lastAuditFromBuf(t, &buf)
	if ev["auth_method"] != "oidc_callback" || ev["event_id"] != eventAccessDenied || ev["status"] != float64(http.StatusUnauthorized) {
		t.Fatalf("audit = %v, want oidc_callback/access_denied/401", ev)
	}
	if raw := buf.String(); strings.Contains(raw, "secret-code") || strings.Contains(raw, flow.State) {
		t.Fatalf("audit leaked secret: %s", raw)
	}
}

func TestCallbackIDTokenVerifyEmitsAccessDeniedAudit(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	// Mock OIDC discovery + JWKS so the verifier can be instantiated without
	// reaching the real Keycloak. The token itself will be intentionally invalid,
	// so the JWKS content is irrelevant beyond satisfying discovery.
	var discoverySrv *httptest.Server
	discoverySrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                discoverySrv.URL,
				"authorization_endpoint":                discoverySrv.URL + "/auth",
				"token_endpoint":                        discoverySrv.URL + "/token",
				"jwks_uri":                              discoverySrv.URL + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer discoverySrv.Close()

	provider, err := oidc.NewProvider(ctx, discoverySrv.URL)
	if err != nil {
		t.Fatalf("create mock provider: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: "test-client"})

	// Token endpoint returns a payload with an unparseable id_token, forcing
	// verifier.Verify to fail and exercise the 401 audit path.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "dummy-access",
			"token_type":   "Bearer",
			"id_token":     "invalid-not-a-jwt",
		})
	}))
	defer tokenSrv.Close()

	var buf bytes.Buffer
	a := &Authenticator{
		store:    st,
		log:      slog.New(slog.NewJSONHandler(&buf, nil)),
		provider: provider,
		verifier: verifier,
		oauth: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://app.test/api/auth/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenSrv.URL,
			},
		},
	}

	flow := store.AuthFlow{
		State:        "verify-state-" + time.Now().Format("150405.000000"),
		Nonce:        "test-nonce",
		PKCEVerifier: "test-verifier",
		ReturnTo:     "/",
		ExpiresAt:    time.Now().Add(authFlowTTL),
	}
	if err := st.CreateAuthFlow(ctx, flow); err != nil {
		t.Fatalf("create auth flow: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state="+flow.State+"&code=secret-code", nil)
	req.AddCookie(&http.Cookie{Name: authStateCookieName(false), Value: flow.State})
	rr := httptest.NewRecorder()
	a.handleCallback(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	ev := lastAuditFromBuf(t, &buf)
	if ev["auth_method"] != "oidc_callback" || ev["event_id"] != eventAccessDenied || ev["status"] != float64(http.StatusUnauthorized) {
		t.Fatalf("audit = %v, want oidc_callback/access_denied/401", ev)
	}
	if raw := buf.String(); strings.Contains(raw, "secret-code") || strings.Contains(raw, flow.State) || strings.Contains(raw, "invalid-not-a-jwt") {
		t.Fatalf("audit leaked secret: %s", raw)
	}
}

func lastAuditFromBuf(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) == 0 || len(lines[len(lines)-1]) == 0 {
		t.Fatal("no audit log line emitted")
	}
	var ev map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("log line is not JSON: %v (%s)", err, lines[len(lines)-1])
	}
	return ev
}
