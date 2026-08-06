package backend

import (
	"context"
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
				req.AddCookie(&http.Cookie{Name: authStateCookieName, Value: tc.cookieState})
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
	req.AddCookie(&http.Cookie{Name: authStateCookieName, Value: state})
	rr := httptest.NewRecorder()
	(&Authenticator{}).handleCallback(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("client Set-Cookie count = %d, want 1", len(cookies))
	}
	if cookies[0].Name != authStateCookieName || cookies[0].MaxAge != -1 || cookies[0].Path != authStateCookiePath {
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
				req.AddCookie(&http.Cookie{Name: authStateCookieName, Value: tc.cookieState})
			}
			if got := authStateMatches(req, state); got != tc.want {
				t.Fatalf("authStateMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuthStateCookiePathCoversCallbackRoute(t *testing.T) {
	const callbackPath = "/api/auth/callback"
	cookiePath := strings.TrimSuffix(authStateCookiePath, "/")
	if authStateCookiePath == "" || !strings.HasPrefix(callbackPath, cookiePath+"/") {
		t.Fatalf("auth-state cookie path %q does not cover callback route %q", authStateCookiePath, callbackPath)
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
	if cookie.Name != authStateCookieName || cookie.Value != "expected-state" {
		t.Fatalf("cookie identity = %q=%q, want %q=%q", cookie.Name, cookie.Value, authStateCookieName, "expected-state")
	}
	if cookie.Path != authStateCookiePath || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie attributes = path %q, HttpOnly %v, Secure %v, SameSite %v", cookie.Path, cookie.HttpOnly, cookie.Secure, cookie.SameSite)
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
	if cleared[0].Name != authStateCookieName || cleared[0].Path != authStateCookiePath || cleared[0].MaxAge != -1 || !cleared[0].HttpOnly || !cleared[0].Secure || cleared[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("clear cookie = %#v, want matching expired auth-state cookie", cleared[0])
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
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == authStateCookieName {
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
	if stateCookie.Path != authStateCookiePath || !stateCookie.HttpOnly || !stateCookie.Secure || stateCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("login auth-state cookie attributes = %#v", stateCookie)
	}

	flow, err := st.TakeAuthFlow(ctx, state)
	if err != nil {
		t.Fatalf("stored auth flow = %v", err)
	}
	if flow.ReturnTo != "/dashboard" || flow.Nonce == "" || flow.PKCEVerifier == "" {
		t.Fatalf("stored auth flow = %+v", flow)
	}
}
