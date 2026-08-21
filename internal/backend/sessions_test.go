package backend

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// TestSessionTTLEnforcedByAuthenticator verifies SESSION_TTL is bounded to the
// documented 15m..24h window (#189). The worst-case stale-role window must not
// be unbounded (the 720h example in the finding).
func TestSessionTTLEnforcedByAuthenticator(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ttl     time.Duration
		wantErr bool
	}{
		{name: "default zero -> ok (becomes 12h)", ttl: 0, wantErr: false},
		{name: "default 12h -> ok", ttl: 12 * time.Hour, wantErr: false},
		{name: "min 15m -> ok", ttl: 15 * time.Minute, wantErr: false},
		{name: "max 24h -> ok", ttl: 24 * time.Hour, wantErr: false},
		{name: "too short 1m -> reject", ttl: time.Minute, wantErr: true},
		{name: "too long 720h -> reject", ttl: 720 * time.Hour, wantErr: true},
		{name: "just over max 25h -> reject", ttl: 25 * time.Hour, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAuthenticator(context.Background(), nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), AuthConfig{
				Issuer:       "https://example.com",
				ClientID:     "id",
				ClientSecret: "secret",
				SessionTTL:   tc.ttl,
			})
			if tc.wantErr && err == nil {
				t.Fatalf("SessionTTL %v: expected error, got nil", tc.ttl)
			}
			if !tc.wantErr && err != nil && strings.Contains(err.Error(), "SESSION_TTL") {
				t.Fatalf("SessionTTL %v: unexpected TTL error: %v", tc.ttl, err)
			}
			// When we expected success, the only error we tolerate is the OIDC
			// discovery failure (no IdP at example.com) — TTL already validated.
			if !tc.wantErr && err != nil && !strings.Contains(err.Error(), "oidc discovery") {
				t.Fatalf("SessionTTL %v: unexpected error: %v", tc.ttl, err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "SESSION_TTL") {
				t.Fatalf("SessionTTL %v: error %q does not mention SESSION_TTL", tc.ttl, err)
			}
		})
	}
}

// TestSessionConstantsDocumented ensures the bounds match the admin guide.
func TestSessionConstantsDocumented(t *testing.T) {
	if DefaultSessionTTL != 12*time.Hour {
		t.Fatalf("DefaultSessionTTL = %v, want 12h", DefaultSessionTTL)
	}
	if MinSessionTTL != 15*time.Minute {
		t.Fatalf("MinSessionTTL = %v, want 15m", MinSessionTTL)
	}
	if MaxSessionTTL != 24*time.Hour {
		t.Fatalf("MaxSessionTTL = %v, want 24h", MaxSessionTTL)
	}
}

// TestSessionBulkDeleteRequiresSubject and TestSessionDeleteHandlerRequiresID
// smoke-test the routing guards without a DB: missing subject/id is 400 before
// the store is touched (store may be nil for those early-return branches).

func TestSessionBulkDeleteRequiresSubject(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
	s.store = nil
	req := httptest.NewRequest(http.MethodDelete, "/api/sessions", nil)
	rr := httptest.NewRecorder()
	req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	s.handleDeleteSessions(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bulk delete without subject status = %d, want 400", rr.Code)
	}
}

func TestSessionDeleteHandlerRequiresID(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/", nil)
	rr := httptest.NewRecorder()
	req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	s.handleDeleteSession(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("delete without id status = %d, want 400", rr.Code)
	}
}

// TestSessionBulkDeleteReturns404ForUnknownSubject pins the 404 branch
// (sessions.go:64) so a future refactor cannot silently regress to the old
// 200 {"revoked":0} silent-no-op (#189 follow-up).
func TestSessionBulkDeleteReturns404ForUnknownSubjectPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)
	s := &Server{store: st, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
	req := httptest.NewRequest(http.MethodDelete, "/api/sessions?subject=does-not-exist-"+time.Now().Format(time.RFC3339Nano), nil)
	rr := httptest.NewRecorder()
	req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	s.handleDeleteSessions(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("bulk delete unknown subject status = %d, want 404 body %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "no active sessions for subject") {
		t.Fatalf("bulk delete unknown subject body = %q, want 'no active sessions for subject'", rr.Body.String())
	}
}

// TestSessionRevokedAuditConstants ensures the session_revoked event id is a
// distinct, stable vocabulary entry (drives SIEM detections) and does not
// collapse into the generic config_changed / access_denied buckets.

func TestSessionRevokedAuditConstants(t *testing.T) {
	if eventSessionRevoked == eventConfigChanged {
		t.Fatal("eventSessionRevoked must be distinct from eventConfigChanged")
	}
	if eventSessionRevoked == eventAccessDenied {
		t.Fatal("eventSessionRevoked must be distinct from access_denied")
	}
	if eventSessionRevoked != "session_revoked" {
		t.Fatalf("eventSessionRevoked = %q, want \"session_revoked\"", eventSessionRevoked)
	}
}
