package backend

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReturnToRedirectLocation exercises the real net/http redirect
// serialization the browser sees, mirroring the callback handler's
// dest := firstNonEmpty(safeReturnTo(flow.ReturnTo), postLogin, "/").
func TestReturnToRedirectLocation(t *testing.T) {
	cases := []struct{ returnTo, wantLocation string }{
		{`/dashboard`, `/dashboard`}, // legit relative path preserved
		{`/\evil.com`, `/app`},       // backslash bypass -> safe default
		{`//evil.com`, `/app`},       // scheme-relative -> safe default
		{`https://evil.com`, `/app`}, // absolute -> safe default
	}
	const postLogin = "/app"
	for _, c := range cases {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/callback", nil)
		dest := firstNonEmpty(safeReturnTo(c.returnTo), postLogin, "/")
		http.Redirect(rr, req, dest, http.StatusFound)
		got := rr.Header().Get("Location")
		if got != c.wantLocation {
			t.Errorf("return_to=%q -> Location=%q, want %q", c.returnTo, got, c.wantLocation)
		}
	}
}
