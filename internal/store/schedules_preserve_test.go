package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestUpdateSchedulePreservesEnabledAtomicallyPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	targetID := types.NewID()
	if _, err := st.pool.Exec(ctx, `INSERT INTO targets (id, name, hosts) VALUES ($1, 'preserve-target', ARRAY['preserve.invalid'])`, targetID); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	tsID := types.NewID()
	if _, err := st.pool.Exec(ctx, `INSERT INTO template_sets (id, name) VALUES ($1, 'preserve-ts')`, tsID); err != nil {
		t.Fatalf("insert ts: %v", err)
	}
	policyID := types.NewID()
	if _, err := st.pool.Exec(ctx, `INSERT INTO scan_policies (id, name, template_set_id) VALUES ($1, 'preserve-policy', $2)`, policyID, tsID); err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	next := time.Now().Add(2 * time.Hour).Truncate(time.Minute)
	nextTrue := next

	// Disabled -> omitted preserves disabled and next nil
	disabled, err := st.CreateSchedule(ctx, Schedule{
		Name: "disabled-preserve", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 3 * * *", Enabled: false, NextRunAt: nil,
	})
	if err != nil {
		t.Fatalf("create disabled: %v", err)
	}
	// Attempt update with omitted enabled (nil) and new cron, nextTrue for true case
	newCron := "0 4 * * *"
	if _, err := st.UpdateSchedule(ctx, disabled.ID, Schedule{
		Name: "disabled-renamed", ScanPolicyID: policyID, TargetID: targetID, Cron: newCron, NextRunAt: &nextTrue,
	}, nil); err != nil {
		t.Fatalf("update disabled preserve: %v", err)
	}
	got, _ := st.GetSchedule(ctx, disabled.ID)
	if got.Enabled {
		t.Fatalf("disabled preserve: Enabled true, want false")
	}
	if got.NextRunAt != nil {
		t.Fatalf("disabled preserve: NextRunAt %v, want nil", *got.NextRunAt)
	}
	if got.Cron != newCron {
		t.Fatalf("disabled preserve: Cron %q, want %q", got.Cron, newCron)
	}

	// Enabled -> omitted preserves enabled and recomputes next
	enabled, err := st.CreateSchedule(ctx, Schedule{
		Name: "enabled-preserve", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 3 * * *", Enabled: true, NextRunAt: &next,
	})
	if err != nil {
		t.Fatalf("create enabled: %v", err)
	}
	newNext := time.Now().Add(3 * time.Hour).Truncate(time.Minute)
	if _, err := st.UpdateSchedule(ctx, enabled.ID, Schedule{
		Name: "enabled-renamed", ScanPolicyID: policyID, TargetID: targetID, Cron: "0 5 * * *", NextRunAt: &newNext,
	}, nil); err != nil {
		t.Fatalf("update enabled preserve: %v", err)
	}
	got, _ = st.GetSchedule(ctx, enabled.ID)
	if !got.Enabled {
		t.Fatalf("enabled preserve: Enabled false, want true")
	}
	if got.NextRunAt == nil || !got.NextRunAt.Equal(newNext) {
		t.Fatalf("enabled preserve: NextRunAt %v, want %v", got.NextRunAt, newNext)
	}

	// Explicit true: disabled -> enabled
	enabledTrue := true
	if _, err := st.UpdateSchedule(ctx, disabled.ID, Schedule{
		Name: "disabled-explicit-true", ScanPolicyID: policyID, TargetID: targetID, Cron: "0 3 * * *", NextRunAt: &nextTrue,
	}, &enabledTrue); err != nil {
		t.Fatalf("explicit true: %v", err)
	}
	got, _ = st.GetSchedule(ctx, disabled.ID)
	if !got.Enabled || got.NextRunAt == nil {
		t.Fatalf("explicit true: got Enabled %v Next %v, want true/non-nil", got.Enabled, got.NextRunAt)
	}

	// Explicit false: enabled -> disabled
	enabledFalse := false
	if _, err := st.UpdateSchedule(ctx, enabled.ID, Schedule{
		Name: "enabled-explicit-false", ScanPolicyID: policyID, TargetID: targetID, Cron: "0 3 * * *", NextRunAt: &nextTrue,
	}, &enabledFalse); err != nil {
		t.Fatalf("explicit false: %v", err)
	}
	got, _ = st.GetSchedule(ctx, enabled.ID)
	if got.Enabled || got.NextRunAt != nil {
		t.Fatalf("explicit false: got Enabled %v Next %v, want false/nil", got.Enabled, got.NextRunAt)
	}

	// Atomicity: concurrent disable preserved via nil
	// Start enabled, then disable, then omitted update must stay disabled
	raceSched, err := st.CreateSchedule(ctx, Schedule{
		Name: "race-preserve", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 3 * * *", Enabled: true, NextRunAt: &next,
	})
	if err != nil {
		t.Fatalf("create race: %v", err)
	}
	// Concurrent disable
	if _, err := st.UpdateSchedule(ctx, raceSched.ID, Schedule{
		Name: raceSched.Name, ScanPolicyID: policyID, TargetID: targetID, Cron: "0 3 * * *", NextRunAt: nil,
	}, &enabledFalse); err != nil {
		t.Fatalf("race disable: %v", err)
	}
	// Now omitted update (nil) with new cron/nextTrue – must preserve disabled
	raceNext := time.Now().Add(4 * time.Hour).Truncate(time.Minute)
	if _, err := st.UpdateSchedule(ctx, raceSched.ID, Schedule{
		Name: "race-renamed", ScanPolicyID: policyID, TargetID: targetID, Cron: "0 6 * * *", NextRunAt: &raceNext,
	}, nil); err != nil {
		t.Fatalf("race preserve: %v", err)
	}
	got, _ = st.GetSchedule(ctx, raceSched.ID)
	if got.Enabled {
		t.Fatalf("race preserve: Enabled true, want preserved false")
	}
	if got.NextRunAt != nil {
		t.Fatalf("race preserve: NextRunAt %v, want nil (disabled)", *got.NextRunAt)
	}
}
