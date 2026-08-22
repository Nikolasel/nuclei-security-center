package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// TestHandleUpdateSettingsRejectsInvalidWindow exercises the HTTP validation that
// bounds scan_retention_days to [1, MaxScanRetentionDays] (#192). These branches
// return 400 before the store is touched, so they run without a database.
func TestHandleUpdateSettingsRejectsInvalidWindow(t *testing.T) {
	days := func(n int) *int { return &n }
	cases := []struct {
		name       string
		req        updateSettingsRequest
		wantSubstr string
	}{
		{
			name:       "zero window rejected (null-or-unset path)",
			req:        updateSettingsRequest{RetentionEnabled: false, ScanRetentionDays: days(0)},
			wantSubstr: "between 1 and 36500",
		},
		{
			name:       "negative window rejected",
			req:        updateSettingsRequest{RetentionEnabled: false, ScanRetentionDays: days(-5)},
			wantSubstr: "between 1 and 36500",
		},
		{
			name:       "enabled with nil window rejected",
			req:        updateSettingsRequest{RetentionEnabled: true, ScanRetentionDays: nil},
			wantSubstr: "between 1 and 36500",
		},
		{
			name:       "enabled with zero window rejected",
			req:        updateSettingsRequest{RetentionEnabled: true, ScanRetentionDays: days(0)},
			wantSubstr: "between 1 and 36500",
		},
		{
			name:       "maximum+1 rejected",
			req:        updateSettingsRequest{RetentionEnabled: true, ScanRetentionDays: days(store.MaxScanRetentionDays + 1)},
			wantSubstr: "between 1 and 36500",
		},
		{
			name:       "overflow window rejected (106752)",
			req:        updateSettingsRequest{RetentionEnabled: true, ScanRetentionDays: days(106752)},
			wantSubstr: "between 1 and 36500",
		},
		{
			name:       "huge window rejected (int max)",
			req:        updateSettingsRequest{RetentionEnabled: true, ScanRetentionDays: days(2147483647)},
			wantSubstr: "between 1 and 36500",
		},
		{
			name:       "disabled but maximum+1 still rejected",
			req:        updateSettingsRequest{RetentionEnabled: false, ScanRetentionDays: days(store.MaxScanRetentionDays + 1)},
			wantSubstr: "between 1 and 36500",
		},
		{
			name:       "null when disabled is allowed (no error)",
			req:        updateSettingsRequest{RetentionEnabled: false, ScanRetentionDays: nil},
			wantSubstr: "", // should not be rejected
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Store is nil: rejection paths must not touch it.
			s := &Server{store: nil, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
			body, _ := json.Marshal(tc.req)
			req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
			rr := httptest.NewRecorder()
			didPanic := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						didPanic = true
					}
				}()
				s.handleUpdateSettings(rr, req)
			}()
			if tc.wantSubstr == "" {
				// Expect not 400 — but without a store the handler panics/500s on
				// UpdateAppSettings. Any outcome that is not the validation 400 proves
				// it passed validation.
				if !didPanic && rr.Code == http.StatusBadRequest && strings.Contains(rr.Body.String(), "between 1 and 36500") {
					t.Fatalf("unexpected validation rejection for allowed request %+v: %s", tc.req, rr.Body.String())
				}
				if didPanic {
					// Nil-store panic is expected for allowed path without DB.
					return
				}
				if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusOK {
					t.Logf("allowed request reached store path with status %d (expected panic/500 with nil store, or 200 with real store)", rr.Code)
				}
				return
			}
			if didPanic {
				t.Fatalf("unexpected panic for rejected request %+v", tc.req)
			}
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %+v body %q", rr.Code, tc.req, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantSubstr) {
				t.Fatalf("body %q does not contain %q", rr.Body.String(), tc.wantSubstr)
			}
		})
	}
}

// TestHandleUpdateSettingsAcceptsMaximumWindowPostgres pins the upper bound as
// accepted and maximum+1 as rejected through the real HTTP handler with a DB.
func TestHandleUpdateSettingsAcceptsMaximumWindowPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)
	s := &Server{store: st, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}

	// Helper to PUT /api/settings and return status/body.
	put := func(days *int, enabled bool) (int, string) {
		reqBody := updateSettingsRequest{RetentionEnabled: enabled, ScanRetentionDays: days, RetentionIncludeAdhoc: false}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:8080")
		req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin-test-" + time.Now().Format(time.RFC3339Nano), Roles: []string{RoleAdmin}}))
		rr := httptest.NewRecorder()
		// Call via mutation wrapper to exercise RBAC, but directly via handler
		// with admin identity is sufficient to pin validation.
		s.handleUpdateSettings(rr, req)
		return rr.Code, rr.Body.String()
	}

	days := func(n int) *int { return &n }

	// Maximum is accepted.
	if code, body := put(days(store.MaxScanRetentionDays), true); code != http.StatusOK {
		t.Fatalf("PUT max window status = %d, want 200 body %q", code, body)
	}
	// Verify it persisted.
	settings, err := st.GetAppSettings(ctx)
	if err != nil {
		t.Fatalf("GetAppSettings after max: %v", err)
	}
	if settings.ScanRetentionDays == nil || *settings.ScanRetentionDays != store.MaxScanRetentionDays {
		t.Fatalf("persisted ScanRetentionDays = %v, want %d", settings.ScanRetentionDays, store.MaxScanRetentionDays)
	}
	if !settings.RetentionActive() {
		t.Fatal("RetentionActive after max = false, want true")
	}
	if cutoff := settings.RetentionCutoff(time.Now()); cutoff.IsZero() || !cutoff.Before(time.Now()) {
		t.Fatalf("RetentionCutoff after max = %v, want non-zero before now", cutoff)
	}

	// Maximum+1 is rejected with 400 and does not change the stored window.
	if code, body := put(days(store.MaxScanRetentionDays+1), true); code != http.StatusBadRequest {
		t.Fatalf("PUT max+1 status = %d, want 400 body %q", code, body)
	} else if !strings.Contains(body, "between 1 and 36500") {
		t.Fatalf("PUT max+1 body %q does not contain bound message", body)
	}
	settings2, err := st.GetAppSettings(ctx)
	if err != nil {
		t.Fatalf("GetAppSettings after max+1 reject: %v", err)
	}
	if settings2.ScanRetentionDays == nil || *settings2.ScanRetentionDays != store.MaxScanRetentionDays {
		t.Fatalf("stored window changed after rejected max+1: got %v, want %d", settings2.ScanRetentionDays, store.MaxScanRetentionDays)
	}

	// Overflow value (106752) also rejected.
	if code, body := put(days(106752), true); code != http.StatusBadRequest {
		t.Fatalf("PUT overflow 106752 status = %d, want 400 body %q", code, body)
	}

	// Disabled with null is accepted (clears window).
	if code, body := put(nil, false); code != http.StatusOK {
		t.Fatalf("PUT disabled+null status = %d, want 200 body %q", code, body)
	}
}

// TestRetentionCutoffIsCalendrical ensures the cutoff uses AddDate, not
// time.Duration, so the mapping is exact for Max and never produces a future
// cutoff (the old Duration path wrapped to 2318 for 106752).
func TestRetentionCutoffIsCalendrical(t *testing.T) {
	days := func(n int) *int { return &n }
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	wantMax := now.AddDate(0, 0, -store.MaxScanRetentionDays)
	s := store.AppSettings{RetentionEnabled: true, ScanRetentionDays: days(store.MaxScanRetentionDays)}
	got := s.RetentionCutoff(now)
	if !got.Equal(wantMax) {
		t.Fatalf("RetentionCutoff(max) = %v, want %v", got, wantMax)
	}
	if !got.Before(now) {
		t.Fatalf("RetentionCutoff(max) = %v not before now %v", got, now)
	}
	// Max+1 and overflow are fail-closed.
	for _, n := range []int{store.MaxScanRetentionDays + 1, 106752, 2147483647} {
		s := store.AppSettings{RetentionEnabled: true, ScanRetentionDays: days(n)}
		if s.RetentionActive() {
			t.Fatalf("RetentionActive(%d) = true, want false", n)
		}
		if cutoff := s.RetentionCutoff(now); !cutoff.IsZero() {
			t.Fatalf("RetentionCutoff(%d) = %v, want zero", n, cutoff)
		}
	}
}
