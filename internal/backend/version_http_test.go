package backend

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/version"
)

func TestVersionAuthDisabledMatchesCurrent(t *testing.T) {
	srv := NewServer(nil, nil, nil, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got version.Info
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != version.Current() {
		t.Fatalf("body = %+v, want %+v", got, version.Current())
	}
	if got.Version == "" || strings.Contains(got.Version, "devel") {
		t.Fatalf("version = %q", got.Version)
	}
}

func TestVersionRequiresAuthentication(t *testing.T) {
	srv := NewServer(nil, nil, &Authenticator{}, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "\"version\"") || strings.Contains(rec.Body.String(), "\"commit\"") {
		t.Fatalf("unauthenticated body leaked version JSON: %s", rec.Body.String())
	}
}
