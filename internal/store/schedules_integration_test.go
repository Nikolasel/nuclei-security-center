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
	if _, err := st.UpdateSchedule(ctx, second.ID, Schedule{
		Name: "NIGHTLY SCAN", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 6 * * *", Enabled: true, NextRunAt: &next,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateSchedule(case duplicate of %s) = %v, want ErrConflict", first.ID, err)
	}
}
