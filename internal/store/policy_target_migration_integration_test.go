package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestTargetIndependentPoliciesUpgradePostgres proves migration 0036 preserves
// existing schedules by copying their policy-owned target, then establishes the
// new ownership/cascade contract. It is opt-in with the other real-PostgreSQL
// migration tests.
func TestTargetIndependentPoliciesUpgradePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn, "0035_endpoint_coverage_lookup.sql")

	targetID, templateSetID, policyID, scheduleID :=
		types.NewID(), types.NewID(), types.NewID(), types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts)
		 VALUES ($1, 'policy-target-upgrade', ARRAY['upgrade.invalid'])`,
		targetID,
	); err != nil {
		t.Fatalf("seed pre-0036 target: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO template_sets (id, name, dynamic_all)
		 VALUES ($1, 'policy-target-upgrade-templates', TRUE)`,
		templateSetID,
	); err != nil {
		t.Fatalf("seed pre-0036 template set: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO scan_policies (id, name, target_id, template_set_id)
		 VALUES ($1, 'policy-target-upgrade-policy', $2, $3)`,
		policyID, targetID, templateSetID,
	); err != nil {
		t.Fatalf("seed pre-0036 policy: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO schedules (id, name, scan_policy_id, cron, enabled)
		 VALUES ($1, 'policy-target-upgrade-schedule', $2, '0 3 * * *', TRUE)`,
		scheduleID, policyID,
	); err != nil {
		t.Fatalf("seed pre-0036 schedule: %v", err)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("upgrade through target-independent policies: %v", err)
	}

	policy, err := st.GetScanPolicy(ctx, policyID)
	if err != nil {
		t.Fatalf("read upgraded policy: %v", err)
	}
	if policy.TemplateSetID != templateSetID {
		t.Fatalf("upgraded policy template_set_id = %q, want %q", policy.TemplateSetID, templateSetID)
	}
	schedule, err := st.GetSchedule(ctx, scheduleID)
	if err != nil {
		t.Fatalf("read upgraded schedule: %v", err)
	}
	if schedule.TargetID != targetID || schedule.ScanPolicyID != policyID {
		t.Fatalf("upgraded schedule refs = target:%q policy:%q, want %q/%q",
			schedule.TargetID, schedule.ScanPolicyID, targetID, policyID)
	}

	var policyTargetColumns int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*)
		   FROM information_schema.columns
		  WHERE table_schema = current_schema()
		    AND table_name = 'scan_policies'
		    AND column_name = 'target_id'`,
	).Scan(&policyTargetColumns); err != nil {
		t.Fatalf("inspect upgraded policy schema: %v", err)
	}
	if policyTargetColumns != 0 {
		t.Fatalf("scan_policies.target_id still exists after upgrade")
	}

	// Exercise the post-migration CRUD shapes as well as reading migrated rows.
	rateLimit := 25
	createdPolicy, err := st.CreateScanPolicy(ctx, ScanPolicy{
		Name:          "reusable-policy",
		TemplateSetID: templateSetID,
		RateLimit:     &rateLimit,
	})
	if err != nil {
		t.Fatalf("create target-independent policy: %v", err)
	}
	createdPolicy.Name = "reusable-policy-updated"
	if _, err := st.UpdateScanPolicy(ctx, createdPolicy.ID, createdPolicy); err != nil {
		t.Fatalf("update target-independent policy: %v", err)
	}
	createdSchedule, err := st.CreateSchedule(ctx, Schedule{
		Name:         "new-shape-schedule",
		ScanPolicyID: createdPolicy.ID,
		TargetID:     targetID,
		Cron:         "0 4 * * *",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("create schedule with explicit target: %v", err)
	}
	createdSchedule.Cron = "0 5 * * *"
	if _, err := st.UpdateSchedule(ctx, createdSchedule.ID, createdSchedule); err != nil {
		t.Fatalf("update schedule with explicit target: %v", err)
	}
	secondTarget, err := st.CreateTarget(ctx, Target{
		Name:  "second-policy-target",
		Hosts: []string{"second.invalid"},
	})
	if err != nil {
		t.Fatalf("create second target: %v", err)
	}
	secondSchedule, err := st.CreateSchedule(ctx, Schedule{
		Name:         "same-policy-second-target",
		ScanPolicyID: createdPolicy.ID,
		TargetID:     secondTarget.ID,
		Cron:         "0 6 * * *",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("reuse policy with second target: %v", err)
	}

	// The target owns schedules but no longer owns reusable policies.
	if err := st.DeleteTarget(ctx, targetID); err != nil {
		t.Fatalf("delete migrated target: %v", err)
	}
	var deletedTargetSchedules, secondTargetSchedules, policies int
	if err := st.pool.QueryRow(ctx,
		`SELECT
		    (SELECT count(*) FROM schedules WHERE id = $1 OR id = $2),
		    (SELECT count(*) FROM schedules WHERE id = $3 AND target_id = $4),
		    (SELECT count(*) FROM scan_policies WHERE id = $5 OR id = $6)`,
		scheduleID, createdSchedule.ID, secondSchedule.ID, secondTarget.ID, policyID, createdPolicy.ID,
	).Scan(&deletedTargetSchedules, &secondTargetSchedules, &policies); err != nil {
		t.Fatalf("read post-delete ownership: %v", err)
	}
	if deletedTargetSchedules != 0 || secondTargetSchedules != 1 || policies != 2 {
		t.Fatalf("post-target-delete rows = deleted-target schedules:%d second-target schedules:%d policies:%d, want 0/1/2",
			deletedTargetSchedules, secondTargetSchedules, policies)
	}
}
