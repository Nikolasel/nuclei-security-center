package backend

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSecurityHeadersOnAllResponses(t *testing.T) {
	spa := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("spa"))
	})
	srv := NewServer(nil, nil, nil, nil, spa, slog.New(slog.NewJSONHandler(os.Stdout, nil)), os.TempDir())
	h := srv.Handler()

	paths := []string{"/", "/healthz", "/api/auth/me", "/api/nonexist"}
	for _, p := range paths {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, p, nil)
		h.ServeHTTP(rec, req)

		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("GET %s missing Content-Security-Policy", p)
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("GET %s CSP = %q, want frame-ancestors 'none'", p, csp)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("GET %s X-Content-Type-Options = %q, want nosniff", p, got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Fatalf("GET %s X-Frame-Options = %q, want DENY", p, got)
		}
		if got := rec.Header().Get("Referrer-Policy"); got == "" {
			t.Fatalf("GET %s missing Referrer-Policy", p)
		}
	}
}

func TestSecurityHeadersAlsoCoverAPIErrors(t *testing.T) {
	spa := http.NotFoundHandler()
	srv := NewServer(nil, nil, nil, nil, spa, slog.New(slog.NewJSONHandler(os.Stdout, nil)), os.TempDir())
	h := srv.Handler()

	// An unknown API path returns 404 through the backend's catch-all, and
	// authz denials return 401/403 — all must still carry the hardening headers.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/unknown", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("404 missing CSP")
	}
}
