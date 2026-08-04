package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestBaselineOccurrenceScanScopeConstraintPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	targetA, targetB := types.NewID(), types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts) VALUES
		     ($1, 'scope-a', ARRAY['a.invalid']),
		     ($2, 'scope-b', ARRAY['b.invalid'])`,
		targetA, targetB,
	); err != nil {
		t.Fatalf("insert scope targets: %v", err)
	}
	scanID, err := st.CreateScan(ctx, types.ScanSpec{}, ScanLink{TargetID: targetA})
	if err != nil {
		t.Fatalf("create targeted scan: %v", err)
	}

	if _, err := st.pool.Exec(ctx,
		`INSERT INTO findings (scan_id, target_id, dedup_key, template_id, raw)
		 VALUES ($1, $2, 'mismatch', 'scope-test', '{}'::jsonb)`,
		scanID, targetB,
	); err == nil || !strings.Contains(err.Error(), "findings_scan_scope_fk") {
		t.Fatalf("mismatched occurrence scope insert = %v, want findings_scan_scope_fk violation", err)
	}

	var occurrenceID int64
	if err := st.pool.QueryRow(ctx,
		`INSERT INTO findings (scan_id, target_id, dedup_key, template_id, raw)
		 VALUES ($1, $2, 'matched', 'scope-test', '{}'::jsonb)
		 RETURNING id`,
		scanID, targetA,
	).Scan(&occurrenceID); err != nil {
		t.Fatalf("insert matching occurrence scope: %v", err)
	}

	if _, err := st.pool.Exec(ctx, `DELETE FROM targets WHERE id = $1`, targetA); err != nil {
		t.Fatalf("delete occurrence target: %v", err)
	}
	var scanTarget, occurrenceTarget *string
	if err := st.pool.QueryRow(ctx,
		`SELECT scans.target_id::text, findings.target_id::text
		   FROM scans
		   JOIN findings ON findings.scan_id = scans.id
		  WHERE findings.id = $1`,
		occurrenceID,
	).Scan(&scanTarget, &occurrenceTarget); err != nil {
		t.Fatalf("read cascaded occurrence scope: %v", err)
	}
	if scanTarget != nil || occurrenceTarget != nil {
		t.Fatalf("target deletion scopes = scan:%v occurrence:%v, want both NULL", scanTarget, occurrenceTarget)
	}
}

func TestBaselineTemplateSetExclusionsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	ids := []string{"dynamic-include-one", "dynamic-excluded", "dynamic-include-two"}
	for i, id := range ids {
		if _, err := st.pool.Exec(ctx,
			`INSERT INTO templates
			 (id, source, path, yaml, content_sha256, name, severity, availability)
			 VALUES ($1, 'custom', $2, $3, $4, $5, 'low', 'active')`,
			id, "custom/"+id+".yaml", "id: "+id+"\n", "sha-"+id, id,
		); err != nil {
			t.Fatalf("insert template %d: %v", i, err)
		}
	}

	set, err := st.CreateTemplateSet(ctx, TemplateSet{
		Name:                "exclude mode " + types.NewID(),
		Mode:                TemplateSetModeExclude,
		ExcludedTemplateIDs: []string{" dynamic-excluded "},
	})
	if err != nil {
		t.Fatalf("create exclude set: %v", err)
	}
	if set.MemberCount != 2 || set.ExclusionCount != 1 {
		t.Fatalf("created set counts = members:%d exclusions:%d, want 2/1", set.MemberCount, set.ExclusionCount)
	}

	members, err := st.ListTemplateSetMembers(ctx, set.ID)
	if err != nil {
		t.Fatalf("list effective members: %v", err)
	}
	if len(members) != 2 || members[0].ID == "dynamic-excluded" || members[1].ID == "dynamic-excluded" {
		t.Fatalf("effective members = %#v, want excluded id absent", members)
	}
	exclusions, err := st.ListTemplateSetExclusions(ctx, set.ID)
	if err != nil {
		t.Fatalf("list exclusions: %v", err)
	}
	if len(exclusions) != 1 || exclusions[0].ID != "dynamic-excluded" {
		t.Fatalf("exclusions = %#v, want dynamic-excluded", exclusions)
	}
	if err := st.DeleteCustomTemplate(ctx, "dynamic-excluded"); !errors.Is(err, ErrTemplateSetExclusionInUse) {
		t.Fatalf("delete excluded template = %v, want ErrTemplateSetExclusionInUse", err)
	}

	set, err = st.UpdateTemplateSet(ctx, set.ID, TemplateSet{
		Name:                set.Name,
		Mode:                TemplateSetModeExclude,
		ExcludedTemplateIDs: []string{"dynamic-include-one", "dynamic-include-two"},
	})
	if err != nil {
		t.Fatalf("update exclude mode: %v", err)
	}
	if set.MemberCount != 1 || set.ExclusionCount != 2 {
		t.Fatalf("updated set counts = members:%d exclusions:%d, want 1/2", set.MemberCount, set.ExclusionCount)
	}

	all, err := st.CreateTemplateSet(ctx, TemplateSet{
		Name: "all mode " + types.NewID(), Mode: TemplateSetModeAll,
	})
	if err != nil {
		t.Fatalf("create all set: %v", err)
	}
	if all.MemberCount != 3 || all.ExclusionCount != 0 {
		t.Fatalf("all set counts = members:%d exclusions:%d, want 3/0", all.MemberCount, all.ExclusionCount)
	}

	exact, err := st.CreateTemplateSet(ctx, TemplateSet{
		Name:                "exact exclusions " + types.NewID(),
		ExcludedTemplateIDs: []string{"dynamic-excluded"},
	})
	if !errors.Is(err, ErrTemplateSetExclusionsUnsupported) || exact.ID != "" {
		t.Fatalf("exact create with exclusions = set:%+v err:%v, want ErrTemplateSetExclusionsUnsupported", exact, err)
	}
	exact, err = st.CreateTemplateSet(ctx, TemplateSet{Name: "exact set " + types.NewID()})
	if err != nil {
		t.Fatalf("create exact set: %v", err)
	}
	if _, err := st.ReplaceTemplateSetExclusions(ctx, exact.ID, []string{"dynamic-excluded"}, "test"); !errors.Is(err, ErrTemplateSetExclusionsUnsupported) {
		t.Fatalf("replace exact exclusions = %v, want ErrTemplateSetExclusionsUnsupported", err)
	}
}

func TestBaselineTargetIndependentPolicyOwnershipPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	var policyTargetColumns int
	if err := st.pool.QueryRow(ctx, `
		SELECT count(*)
		  FROM information_schema.columns
		 WHERE table_schema = current_schema()
		   AND table_name = 'scan_policies'
		   AND column_name = 'target_id'`,
	).Scan(&policyTargetColumns); err != nil {
		t.Fatalf("inspect policy schema: %v", err)
	}
	if policyTargetColumns != 0 {
		t.Fatal("scan_policies.target_id exists in beta baseline")
	}

	firstTarget, err := st.CreateTarget(ctx, Target{Name: "first-policy-target", Hosts: []string{"first.invalid"}})
	if err != nil {
		t.Fatalf("create first target: %v", err)
	}
	secondTarget, err := st.CreateTarget(ctx, Target{Name: "second-policy-target", Hosts: []string{"second.invalid"}})
	if err != nil {
		t.Fatalf("create second target: %v", err)
	}
	templateSet, err := st.CreateTemplateSet(ctx, TemplateSet{
		Name: "target-independent-policy-templates", Mode: TemplateSetModeAll,
	})
	if err != nil {
		t.Fatalf("create template set: %v", err)
	}
	policy, err := st.CreateScanPolicy(ctx, ScanPolicy{
		Name: "reusable-policy", TemplateSetID: templateSet.ID,
	})
	if err != nil {
		t.Fatalf("create target-independent policy: %v", err)
	}
	policy.Name = "reusable-policy-updated"
	if _, err := st.UpdateScanPolicy(ctx, policy.ID, policy); err != nil {
		t.Fatalf("update target-independent policy: %v", err)
	}

	firstSchedule, err := st.CreateSchedule(ctx, Schedule{
		Name: "first-target-schedule", ScanPolicyID: policy.ID, TargetID: firstTarget.ID,
		Cron: "0 4 * * *", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create first-target schedule: %v", err)
	}
	secondSchedule, err := st.CreateSchedule(ctx, Schedule{
		Name: "second-target-schedule", ScanPolicyID: policy.ID, TargetID: secondTarget.ID,
		Cron: "0 5 * * *", Enabled: true,
	})
	if err != nil {
		t.Fatalf("reuse policy with second target: %v", err)
	}
	secondSchedule.Cron = "0 6 * * *"
	if _, err := st.UpdateSchedule(ctx, secondSchedule.ID, secondSchedule); err != nil {
		t.Fatalf("update second-target schedule: %v", err)
	}

	if err := st.DeleteTarget(ctx, firstTarget.ID); err != nil {
		t.Fatalf("delete first target: %v", err)
	}
	var firstSchedules, secondSchedules, policies int
	if err := st.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM schedules WHERE id = $1),
			(SELECT count(*) FROM schedules WHERE id = $2 AND target_id = $3),
			(SELECT count(*) FROM scan_policies WHERE id = $4)`,
		firstSchedule.ID, secondSchedule.ID, secondTarget.ID, policy.ID,
	).Scan(&firstSchedules, &secondSchedules, &policies); err != nil {
		t.Fatalf("read post-delete ownership: %v", err)
	}
	if firstSchedules != 0 || secondSchedules != 1 || policies != 1 {
		t.Fatalf("post-target-delete rows = first schedules:%d second schedules:%d policies:%d, want 0/1/1",
			firstSchedules, secondSchedules, policies)
	}
}

func TestBaselineDeleteScanSerializesWithFindingIngestPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	target, err := st.CreateTarget(ctx, Target{
		Name:  "delete-ingest-lock-order-" + types.NewID(),
		Hosts: []string{"delete-ingest.invalid"},
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	finding := types.NucleiFinding{
		TemplateID: "delete-ingest-lock-order",
		Host:       target.Hosts[0],
		MatchedAt:  "https://delete-ingest.invalid",
		Type:       "http",
		Info: types.NucleiInfo{
			Name:     "Delete/ingest lock order",
			Severity: "high",
		},
	}
	raw, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	scanID, err := st.CreateScan(ctx, types.ScanSpec{Targets: target.Hosts}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := st.IngestFinding(ctx, scanID, target.ID, finding, raw); err != nil {
		t.Fatalf("ingest initial finding: %v", err)
	}
	if err := st.MarkComplete(ctx, scanID, "", ""); err != nil {
		t.Fatalf("complete scan: %v", err)
	}

	var occurrenceID, lifecycleID int64
	if err := st.pool.QueryRow(ctx,
		`SELECT id, finding_id FROM findings WHERE scan_id = $1`, scanID,
	).Scan(&occurrenceID, &lifecycleID); err != nil {
		t.Fatalf("read initial occurrence: %v", err)
	}

	writer, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin concurrent ingest transaction: %v", err)
	}
	defer writer.Rollback(context.Background())
	if _, err := writer.Exec(ctx, `
		INSERT INTO findings
		       (scan_id, template_id, name, severity, host, matched_at, type,
		        raw, cve, tags, target_id, dedup_key, finding_id, raw_line,
		        result_discriminator)
		SELECT scan_id, template_id, name, severity, host, matched_at, type,
		       raw, cve, tags, target_id, dedup_key, finding_id, raw_line,
		       result_discriminator
		  FROM findings
		 WHERE id = $1`, occurrenceID); err != nil {
		t.Fatalf("insert concurrent occurrence: %v", err)
	}
	var writerXID string
	if err := writer.QueryRow(ctx, `
		SELECT transactionid::text
		  FROM pg_locks
		 WHERE pid = pg_backend_pid()
		   AND locktype = 'transactionid'
		   AND mode = 'ExclusiveLock'
		   AND granted`).Scan(&writerXID); err != nil {
		t.Fatalf("read concurrent ingest transaction id lock: %v", err)
	}

	deleteErr := make(chan error, 1)
	go func() {
		_, _, err := st.DeleteScan(ctx, scanID)
		deleteErr <- err
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := st.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				  FROM pg_locks
				 WHERE locktype = 'transactionid'
				   AND transactionid::text = $1
				   AND NOT granted
			)`, writerXID).Scan(&waiting); err != nil {
			t.Fatalf("inspect blocked delete: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DeleteScan did not block behind the in-flight occurrence writer")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := writer.Exec(ctx,
		`UPDATE finding_lifecycle SET severity = severity WHERE id = $1`, lifecycleID,
	); err != nil {
		t.Fatalf("concurrent lifecycle update deadlocked with DeleteScan: %v", err)
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatalf("commit concurrent ingest transaction: %v", err)
	}
	if err := <-deleteErr; err != nil {
		t.Fatalf("delete scan after concurrent ingest: %v", err)
	}

	var lifecycleRows, occurrenceRows int
	if err := st.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM finding_lifecycle WHERE id = $1),
			(SELECT count(*) FROM findings WHERE scan_id = $2)`,
		lifecycleID, scanID,
	).Scan(&lifecycleRows, &occurrenceRows); err != nil {
		t.Fatalf("read repaired lifecycle state: %v", err)
	}
	if lifecycleRows != 0 || occurrenceRows != 0 {
		t.Fatalf("post-delete rows = lifecycle:%d occurrences:%d, want 0/0", lifecycleRows, occurrenceRows)
	}
}
