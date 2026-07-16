package backend

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// isAuthBackendFault must treat ErrNotFound (no such session / unknown / expired
// token) as a credential failure, not an infrastructure fault (#82). Any other
// non-nil error is a backend fault and must yield a 503.
func TestIsAuthBackendFault(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"ErrNotFound", store.ErrNotFound, false},
		{"wrapped ErrNotFound", &wrapErr{store.ErrNotFound}, false},
		{"plain error", errors.New("boom"), true},
		{"pgx-style err", errors.New("failed SASL auth: FATAL: password authentication failed for user \"nuclei\""), true},
	}
	for _, c := range cases {
		if got := isAuthBackendFault(c.err); got != c.want {
			t.Errorf("%s: isAuthBackendFault = %v, want %v", c.name, got, c.want)
		}
	}
}

type wrapErr struct{ e error }

func (w *wrapErr) Error() string { return "wrap: " + w.e.Error() }
func (w *wrapErr) Unwrap() error { return w.e }

// serviceUnavailable must write a 503 with a Retry-After header and a generic
// body (no internal detail leaked, CWE-209), and log the underlying fault at
// ERROR so the trail is preserved (#82).
func TestServiceUnavailable(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{log: slog.New(slog.NewJSONHandler(&buf, nil))}

	rr := httptest.NewRecorder()
	s.serviceUnavailable(rr, "get session", errors.New("connection refused"))

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header missing")
	}
	if strings.Contains(rr.Body.String(), "connection refused") {
		t.Errorf("body leaked internal detail: %q", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "service temporarily unavailable") {
		t.Errorf("body = %q, want generic message", rr.Body.String())
	}
	if !strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Errorf("expected ERROR-level log, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "connection refused") {
		t.Errorf("log line missing the underlying error: %s", buf.String())
	}
}

// With auth enabled and no cookie, requireAuth must return 401 (not 503).
// This pins the unchanged "no cookie" behaviour and exercises the new
// identityFromRequest signature at the boundary that has the most risk of a
// regression.
func TestRequireAuthNoCookieReturns401(t *testing.T) {
	s := &Server{auth: &Authenticator{cfg: AuthConfig{CookieName: "nsc_session"}}, log: slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)

	s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler should not be reached on missing session")
	})(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}
