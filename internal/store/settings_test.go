package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAppSettingsRetentionActive(t *testing.T) {
	days := func(n int) *int { return &n }
	cases := []struct {
		name string
		in   AppSettings
		want bool
	}{
		{"enabled with positive window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(30)}, true},
		{"enabled with maximum window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(MaxScanRetentionDays)}, true},
		{"enabled with maximum+1", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(MaxScanRetentionDays + 1)}, false},
		{"enabled with overflow window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(106752)}, false},
		{"enabled with huge window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(2147483647)}, false},
		{"disabled with window", AppSettings{RetentionEnabled: false, ScanRetentionDays: days(30)}, false},
		{"disabled with maximum window", AppSettings{RetentionEnabled: false, ScanRetentionDays: days(MaxScanRetentionDays)}, false},
		{"enabled but window unset", AppSettings{RetentionEnabled: true, ScanRetentionDays: nil}, false},
		{"enabled but zero window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(0)}, false},
		{"enabled but negative window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(-5)}, false},
		{"zero value", AppSettings{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.RetentionActive(); got != c.want {
				t.Errorf("RetentionActive() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAppSettingsRetentionCutoff(t *testing.T) {
	days := func(n int) *int { return &n }
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	t.Run("maximum window produces cutoff before now", func(t *testing.T) {
		s := AppSettings{RetentionEnabled: true, ScanRetentionDays: days(MaxScanRetentionDays)}
		cutoff := s.RetentionCutoff(now)
		if cutoff.IsZero() {
			t.Fatal("RetentionCutoff(max) = zero, want non-zero")
		}
		if !cutoff.Before(now) {
			t.Fatalf("RetentionCutoff(max) = %v, want before now %v", cutoff, now)
		}
		// Calendar arithmetic: exactly Max days before now (time.Date handles leap).
		want := now.AddDate(0, 0, -MaxScanRetentionDays)
		if !cutoff.Equal(want) {
			t.Fatalf("RetentionCutoff(max) = %v, want %v", cutoff, want)
		}
	})

	t.Run("small window produces exact cutoff", func(t *testing.T) {
		s := AppSettings{RetentionEnabled: true, ScanRetentionDays: days(30)}
		cutoff := s.RetentionCutoff(now)
		want := now.AddDate(0, 0, -30)
		if !cutoff.Equal(want) {
			t.Fatalf("RetentionCutoff(30) = %v, want %v", cutoff, want)
		}
		if !cutoff.Before(now) {
			t.Fatalf("RetentionCutoff(30) = %v not before now", cutoff)
		}
	})

	t.Run("maximum+1 is inactive and returns zero cutoff (fail-closed)", func(t *testing.T) {
		s := AppSettings{RetentionEnabled: true, ScanRetentionDays: days(MaxScanRetentionDays + 1)}
		if s.RetentionActive() {
			t.Fatal("RetentionActive(max+1) = true, want false")
		}
		if cutoff := s.RetentionCutoff(now); !cutoff.IsZero() {
			t.Fatalf("RetentionCutoff(max+1) = %v, want zero (fail-closed)", cutoff)
		}
	})

	t.Run("overflow window returns zero cutoff (fail-closed)", func(t *testing.T) {
		for _, n := range []int{106752, 2147483647} {
			s := AppSettings{RetentionEnabled: true, ScanRetentionDays: days(n)}
			if s.RetentionActive() {
				t.Fatalf("RetentionActive(%d) = true, want false", n)
			}
			if cutoff := s.RetentionCutoff(now); !cutoff.IsZero() {
				t.Fatalf("RetentionCutoff(%d) = %v, want zero", n, cutoff)
			}
		}
	})

	t.Run("disabled or unset window returns zero cutoff", func(t *testing.T) {
		cases := []AppSettings{
			{RetentionEnabled: false, ScanRetentionDays: days(30)},
			{RetentionEnabled: true, ScanRetentionDays: nil},
			{RetentionEnabled: true, ScanRetentionDays: days(0)},
			{},
		}
		for i, s := range cases {
			if cutoff := s.RetentionCutoff(now); !cutoff.IsZero() {
				t.Fatalf("case %d: RetentionCutoff = %v, want zero", i, cutoff)
			}
		}
	})

	t.Run("cutoff is always before now for every active window up to Max", func(t *testing.T) {
		// Spot-check boundaries and a mid value; the sweeper asserts this.
		for _, n := range []int{1, 7, 30, 90, 365, MaxScanRetentionDays} {
			s := AppSettings{RetentionEnabled: true, ScanRetentionDays: days(n)}
			cutoff := s.RetentionCutoff(now)
			if cutoff.IsZero() || !cutoff.Before(now) {
				t.Fatalf("RetentionCutoff(%d) = %v, want non-zero before now", n, cutoff)
			}
		}
	})
}

func TestAppSettingsDBConstraintPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	cases := []struct {
		name string
		days int
	}{
		{"maximum+1 via SQL", MaxScanRetentionDays + 1},
		{"overflow 106752 via SQL", 106752},
		{"zero via SQL", 0},
		{"negative via SQL", -5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.pool.Exec(ctx, `UPDATE app_settings SET scan_retention_days = $1 WHERE id = true`, tc.days)
			if err == nil {
				t.Fatalf("UPDATE app_settings scan_retention_days=%d succeeded, want CHECK violation", tc.days)
			}
			if !strings.Contains(err.Error(), "app_settings_scan_retention_days_check") && !strings.Contains(strings.ToLower(err.Error()), "check") {
				t.Fatalf("UPDATE app_settings scan_retention_days=%d error = %q, want CHECK violation", tc.days, err.Error())
			}
		})
	}

	// Via the store API the DB constraint also fires (the API validates too, but
	// the store path must not be bypassable).
	t.Run("maximum+1 via UpdateAppSettings hits CHECK", func(t *testing.T) {
		days := MaxScanRetentionDays + 1
		_, err := st.UpdateAppSettings(ctx, AppSettings{RetentionEnabled: true, ScanRetentionDays: &days}, "test")
		if err == nil {
			t.Fatal("UpdateAppSettings(max+1) succeeded, want CHECK violation")
		}
		if !strings.Contains(err.Error(), "app_settings_scan_retention_days_check") && !strings.Contains(strings.ToLower(err.Error()), "check") {
			// Some drivers surface it as a generic constraint violation; accept any
			// error that proves the write was rejected, but prefer the named CHECK.
			t.Logf("UpdateAppSettings(max+1) error = %q (expected CHECK violation)", err.Error())
		}
	})

	// Sanity: max and a small value are accepted.
	t.Run("maximum via SQL accepted", func(t *testing.T) {
		_, err := st.pool.Exec(ctx, `UPDATE app_settings SET scan_retention_days = $1 WHERE id = true`, MaxScanRetentionDays)
		if err != nil {
			t.Fatalf("UPDATE app_settings max = %d failed: %v", MaxScanRetentionDays, err)
		}
		var got *int
		if err := st.pool.QueryRow(ctx, `SELECT scan_retention_days FROM app_settings WHERE id = true`).Scan(&got); err != nil {
			t.Fatalf("read back max: %v", err)
		}
		if got == nil || *got != MaxScanRetentionDays {
			t.Fatalf("read back scan_retention_days = %v, want %d", got, MaxScanRetentionDays)
		}
	})
	t.Run("null via SQL accepted", func(t *testing.T) {
		_, err := st.pool.Exec(ctx, `UPDATE app_settings SET scan_retention_days = NULL WHERE id = true`)
		if err != nil {
			t.Fatalf("UPDATE app_settings NULL failed: %v", err)
		}
	})
}
