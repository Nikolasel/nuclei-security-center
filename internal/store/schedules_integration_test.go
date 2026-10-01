package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestScheduleNamesAreCaseInsensitivePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	targetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts) VALUES ($1, 'schedule-name-target', ARRAY['sched.invalid'])`,
		targetID); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	templateSetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO template_sets (id, name) VALUES ($1, 'schedule-name-templates')`,
		templateSetID); err != nil {
		t.Fatalf("insert template set: %v", err)
	}
	policyID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO scan_policies (id, name, template_set_id) VALUES ($1, 'schedule-name-policy', $2)`,
		policyID, templateSetID); err != nil {
		t.Fatalf("insert scan policy: %v", err)
	}

	next := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	first, err := st.CreateSchedule(ctx, Schedule{
		Name: "Nightly scan", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 3 * * *", Enabled: true, NextRunAt: &next,
	})
	if err != nil {
		t.Fatalf("CreateSchedule(first): %v", err)
	}
	if _, err := st.CreateSchedule(ctx, Schedule{
		Name: "nightly scan", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 4 * * *", Enabled: true, NextRunAt: &next,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateSchedule(case duplicate) = %v, want ErrConflict", err)
	}

	second, err := st.CreateSchedule(ctx, Schedule{
		Name: "Another schedule", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 5 * * *", Enabled: true, NextRunAt: &next,
	})
	if err != nil {
		t.Fatalf("CreateSchedule(distinct): %v", err)
	}
	enabled := true
	if _, err := st.UpdateSchedule(ctx, second.ID, Schedule{
		Name: "NIGHTLY SCAN", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 6 * * *", NextRunAt: &next,
	}, &enabled); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateSchedule(case duplicate of %s) = %v, want ErrConflict", first.ID, err)
	}
}

func TestScheduleTimezoneRoundTripPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	targetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts) VALUES ($1, 'schedule-tz-target', ARRAY['sched-tz.invalid'])`,
		targetID); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	templateSetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO template_sets (id, name) VALUES ($1, 'schedule-tz-templates')`,
		templateSetID); err != nil {
		t.Fatalf("insert template set: %v", err)
	}
	policyID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO scan_policies (id, name, template_set_id) VALUES ($1, 'schedule-tz-policy', $2)`,
		policyID, templateSetID); err != nil {
		t.Fatalf("insert scan policy: %v", err)
	}

	next := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	created, err := st.CreateSchedule(ctx, Schedule{
		Name: "tz-roundtrip", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 3 * * *", Timezone: "America/New_York", Enabled: true, NextRunAt: &next,
	})
	if err != nil {
		t.Fatalf("CreateSchedule: %v", err)
	}
	if created.Timezone != "America/New_York" {
		t.Fatalf("CreateSchedule Timezone = %q, want America/New_York", created.Timezone)
	}
	got, err := st.GetSchedule(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSchedule: %v", err)
	}
	if got.Timezone != "America/New_York" {
		t.Fatalf("GetSchedule Timezone = %q, want America/New_York", got.Timezone)
	}

	omitted, err := st.CreateSchedule(ctx, Schedule{
		Name: "tz-default", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 4 * * *", Enabled: true, NextRunAt: &next,
	})
	if err != nil {
		t.Fatalf("CreateSchedule(omitted tz): %v", err)
	}
	if omitted.Timezone != "UTC" {
		t.Fatalf("omitted Timezone = %q, want UTC", omitted.Timezone)
	}

	enabled := true
	updated, err := st.UpdateSchedule(ctx, created.ID, Schedule{
		Name: created.Name, ScanPolicyID: policyID, TargetID: targetID,
		Cron: created.Cron, Timezone: "Europe/Paris", NextRunAt: &next,
	}, &enabled)
	if err != nil {
		t.Fatalf("UpdateSchedule: %v", err)
	}
	if updated.Timezone != "Europe/Paris" {
		t.Fatalf("UpdateSchedule Timezone = %q, want Europe/Paris", updated.Timezone)
	}
}

func TestScheduleTimezoneMigratesCronTZPrefixPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, _ := openEmptyIsolatedPostgres(t, ctx, dsn)

	for _, name := range []string{
		"0001_init.sql",
		"0002_add_scan_policy_response_limits.sql",
		"0003_finding_result_identity.sql",
	} {
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := st.pool.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}

	targetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts) VALUES ($1, 'schedule-tz-migrate-target', ARRAY['sched-tz-mig.invalid'])`,
		targetID); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	templateSetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO template_sets (id, name) VALUES ($1, 'schedule-tz-migrate-templates')`,
		templateSetID); err != nil {
		t.Fatalf("insert template set: %v", err)
	}
	policyID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO scan_policies (id, name, template_set_id) VALUES ($1, 'schedule-tz-migrate-policy', $2)`,
		policyID, templateSetID); err != nil {
		t.Fatalf("insert scan policy: %v", err)
	}

	cronTZID := types.NewID()
	tzID := types.NewID()
	plainID := types.NewID()
	badID := types.NewID()
	cronLocalID := types.NewID()
	tzLocalID := types.NewID()
	tzEmptyID := types.NewID()
	cronEmptyID := types.NewID()
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO schedules (id, name, cron, scan_policy_id, target_id) VALUES
			($1, 'cron-tz-prefixed', 'CRON_TZ=America/New_York 0 3 * * *', $9, $10),
			($2, 'tz-prefixed', 'TZ=Europe/Paris 0 5 * * *', $9, $10),
			($3, 'plain', '0 4 * * *', $9, $10),
			($4, 'bad-prefix', 'CRON_TZ=Not/AZone 0 6 * * *', $9, $10),
			($5, 'cron-tz-local', 'CRON_TZ=Local 0 7 * * *', $9, $10),
			($6, 'tz-local', 'TZ=Local 0 8 * * *', $9, $10),
			($7, 'tz-empty', 'TZ= 0 9 * * *', $9, $10),
			($8, 'cron-tz-empty', 'CRON_TZ= 0 10 * * *', $9, $10)`,
		cronTZID, tzID, plainID, badID, cronLocalID, tzLocalID, tzEmptyID, cronEmptyID, policyID, targetID); err != nil {
		t.Fatalf("insert schedules: %v", err)
	}

	mig, err := migrationsFS.ReadFile("migrations/0004_schedule_timezone.sql")
	if err != nil {
		t.Fatalf("read 0004: %v", err)
	}
	if _, err := st.pool.Exec(ctx, string(mig)); err != nil {
		t.Fatalf("apply 0004: %v", err)
	}

	assertRow := func(id, wantCron, wantTZ string) {
		t.Helper()
		var cron, timezone string
		if err := st.pool.QueryRow(ctx, `SELECT cron, timezone FROM schedules WHERE id = $1`, id).Scan(&cron, &timezone); err != nil {
			t.Fatalf("select %s: %v", id, err)
		}
		if cron != wantCron || timezone != wantTZ {
			t.Errorf("schedule %s: cron=%q timezone=%q, want cron=%q timezone=%q", id, cron, timezone, wantCron, wantTZ)
		}
	}
	assertRow(cronTZID, "0 3 * * *", "America/New_York")
	assertRow(tzID, "0 5 * * *", "Europe/Paris")
	assertRow(plainID, "0 4 * * *", "UTC")
	assertRow(badID, "CRON_TZ=Not/AZone 0 6 * * *", "UTC")
	assertRow(cronLocalID, "0 7 * * *", "UTC")
	assertRow(tzLocalID, "0 8 * * *", "UTC")
	assertRow(tzEmptyID, "0 9 * * *", "UTC")
	assertRow(cronEmptyID, "0 10 * * *", "UTC")
}
