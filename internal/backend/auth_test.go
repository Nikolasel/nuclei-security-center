package backend

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
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
