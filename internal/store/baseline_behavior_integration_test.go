package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

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

// TestBaselineDeleteScanOrdersSharedLifecycleLocksPostgres pins the concurrent
// delete-scan lock order (#177): two scans observing the same results share
// finding_lifecycle rows, so two concurrent DeleteScan transactions both mutate
// those rows. DeleteScan must lock every affected lifecycle row in one
// ascending-id pass after its own scan row and before any mutation — a global
// order that makes a crossing acquisition (and therefore a deadlock) between
// two deletes impossible.
//
// The interleaving is deterministic: a helper transaction plays the dangerous
// half of a second delete by locking its scan row plus only the HIGHEST shared
// lifecycle id, then the real DeleteScan of the other scan must block on that
// row while already owning the LOWEST one. Probing the lowest id with
// FOR UPDATE NOWAIT from a third session proves it; an untouched control row
// proves the lock set is per-row, not table-wide. Deleting the newer scan makes
// the blocking unconditional: both shared rows' latest occurrences belong to
// it, so its NULL-out phase necessarily matches them.
func TestBaselineDeleteScanOrdersSharedLifecycleLocksPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	target, err := st.CreateTarget(ctx, Target{
		Name:  "delete-lock-order-" + types.NewID(),
		Hosts: []string{"delete-lock-order.invalid"},
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	findings := []types.NucleiFinding{
		{
			TemplateID: "delete-order-one",
			Host:       target.Hosts[0],
			MatchedAt:  "https://one.delete-lock-order.invalid",
			Type:       "http",
			Info:       types.NucleiInfo{Name: "Delete order one", Severity: "high"},
		},
		{
			TemplateID: "delete-order-two",
			Host:       target.Hosts[0],
			MatchedAt:  "https://two.delete-lock-order.invalid",
			Type:       "http",
			Info:       types.NucleiInfo{Name: "Delete order two", Severity: "medium"},
		},
	}
	raws := make([][]byte, len(findings))
	for i, f := range findings {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal finding %d: %v", i, err)
		}
		raws[i] = raw
	}

	scanA, err := st.CreateScan(ctx, types.ScanSpec{Targets: target.Hosts}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	scanB, err := st.CreateScan(ctx, types.ScanSpec{Targets: target.Hosts}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create second scan: %v", err)
	}
	// Both shared rows are observed by scanA first and scanB last, so their
	// latest occurrences belong to scanB. Deleting the newer scan therefore
	// provably mutates both rows (its latest_occurrence_id NULL-out matches
	// them), while the helper below holds the higher row out of order.
	for i, f := range findings {
		if err := st.IngestFinding(ctx, scanA, target.ID, f, raws[i]); err != nil {
			t.Fatalf("ingest finding %d into first scan: %v", i, err)
		}
		if err := st.IngestFinding(ctx, scanB, target.ID, f, raws[i]); err != nil {
			t.Fatalf("ingest finding %d into second scan: %v", i, err)
		}
	}
	if err := st.MarkComplete(ctx, scanA, "", ""); err != nil {
		t.Fatalf("complete first scan: %v", err)
	}
	if err := st.MarkComplete(ctx, scanB, "", ""); err != nil {
		t.Fatalf("complete second scan: %v", err)
	}

	var sharedIDs []int64
	rows, err := st.pool.Query(ctx, `
		SELECT DISTINCT f.finding_id
		  FROM findings f
		 WHERE f.scan_id IN ($1, $2)
		   AND f.finding_id IS NOT NULL
		 ORDER BY 1`, scanA, scanB)
	if err != nil {
		t.Fatalf("list shared lifecycle ids: %v", err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatalf("scan shared lifecycle id: %v", err)
		}
		sharedIDs = append(sharedIDs, id)
	}
	rows.Close()
	if len(sharedIDs) != 2 {
		t.Fatalf("shared lifecycle rows = %v, want exactly two", sharedIDs)
	}
	lowID, highID := sharedIDs[0], sharedIDs[1]

	// An unrelated third result neither delete touches: the NOWAIT control.
	control := types.NucleiFinding{
		TemplateID: "delete-order-control",
		Host:       "control.invalid",
		MatchedAt:  "https://control.invalid",
		Type:       "http",
		Info:       types.NucleiInfo{Name: "Delete order control", Severity: "low"},
	}
	controlRaw, err := json.Marshal(control)
	if err != nil {
		t.Fatalf("marshal control finding: %v", err)
	}
	scanC, err := st.CreateScan(ctx, types.ScanSpec{}, ScanLink{})
	if err != nil {
		t.Fatalf("create control scan: %v", err)
	}
	if err := st.IngestFinding(ctx, scanC, "", control, controlRaw); err != nil {
		t.Fatalf("ingest control finding: %v", err)
	}
	if err := st.MarkComplete(ctx, scanC, "", ""); err != nil {
		t.Fatalf("complete control scan: %v", err)
	}
	var controlID int64
	if err := st.pool.QueryRow(ctx,
		`SELECT finding_id FROM findings WHERE scan_id = $1`, scanC,
	).Scan(&controlID); err != nil {
		t.Fatalf("read control lifecycle id: %v", err)
	}

	helper, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin helper transaction: %v", err)
	}
	defer helper.Rollback(context.Background())
	var helperPID int
	if err := helper.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&helperPID); err != nil {
		t.Fatalf("read helper pid: %v", err)
	}
	// Play the dangerous half of a concurrent delete of the older scanA: its
	// own scan row locked first, then the highest shared lifecycle id grabbed
	// out of order. Under unordered locking the real delete below could reach
	// that row without holding the lowest id, and this transaction wanting
	// that same row next would close a deadlock cycle. With ordered locking
	// the delete owns every shared row before it can block here.
	if _, err := helper.Exec(ctx,
		`SELECT state FROM scans WHERE id = $1 FOR UPDATE`, scanA,
	); err != nil {
		t.Fatalf("helper lock first scan: %v", err)
	}
	if _, err := helper.Exec(ctx,
		`SELECT id FROM finding_lifecycle WHERE id = $1 FOR UPDATE`, highID,
	); err != nil {
		t.Fatalf("helper lock highest shared lifecycle: %v", err)
	}

	deleteErr := make(chan error, 1)
	deleteCtx, deleteCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer deleteCancel()
	go func() {
		_, _, err := st.DeleteScan(deleteCtx, scanB)
		deleteErr <- err
	}()

	var blocked bool
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := st.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				  FROM pg_stat_activity
				 WHERE pid <> pg_backend_pid()
				   AND wait_event_type = 'Lock'
				   AND $1 = ANY(pg_blocking_pids(pid))
			)`, helperPID).Scan(&blocked); err != nil {
			t.Fatalf("inspect blocked delete: %v", err)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			if err := helper.Rollback(context.Background()); err != nil {
				t.Fatalf("deadline rollback helper: %v", err)
			}
			select {
			case err := <-deleteErr:
				t.Fatalf("DeleteScan did not block on the highest shared lifecycle row (its error: %v)", err)
			case <-time.After(10 * time.Second):
				t.Fatal("DeleteScan did not block on the highest shared lifecycle row")
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The blocked delete must already hold the LOWEST shared row: acquiring it
	// elsewhere must refuse immediately instead of succeeding behind its back.
	probeBlocked := func(lifecycleID int64) bool {
		ptx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin lock probe: %v", err)
		}
		defer ptx.Rollback(context.Background())
		_, err = ptx.Exec(ctx,
			`SELECT id FROM finding_lifecycle WHERE id = $1 FOR UPDATE NOWAIT`, lifecycleID)
		if err == nil {
			return false
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			t.Fatalf("lock probe of lifecycle %d failed unexpectedly: %v", lifecycleID, err)
		}
		return pgErr.Code == "55P03" // lock_not_available: held by another transaction
	}
	if !probeBlocked(lowID) {
		t.Fatal("DeleteScan reached the highest shared lifecycle row without holding the lowest one")
	}
	if probeBlocked(controlID) {
		t.Fatal("unrelated lifecycle row was locked alongside the shared rows")
	}

	if err := helper.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback helper transaction: %v", err)
	}
	if err := <-deleteErr; err != nil {
		t.Fatalf("delete scan after ordered lifecycle locking: %v", err)
	}

	var firstOccurrences, secondOccurrences, lifecycleRows, repairedRows int
	if err := st.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM findings WHERE scan_id = $1),
			(SELECT count(*) FROM findings WHERE scan_id = $2),
			(SELECT count(*) FROM finding_lifecycle WHERE id = ANY($3)),
			(SELECT count(*) FROM finding_lifecycle
			  WHERE id = ANY($3)
			    AND first_seen_scan = $1
			    AND last_seen_scan = $1
			    AND last_covering_scan = $1)`,
		scanA, scanB, sharedIDs,
	).Scan(&firstOccurrences, &secondOccurrences, &lifecycleRows, &repairedRows); err != nil {
		t.Fatalf("read post-delete state: %v", err)
	}
	if firstOccurrences != 2 || secondOccurrences != 0 || lifecycleRows != 2 || repairedRows != 2 {
		t.Fatalf("post-delete state = occurrences A:%d B:%d lifecycle:%d repaired-to-A:%d, want 2/0/2/2",
			firstOccurrences, secondOccurrences, lifecycleRows, repairedRows)
	}
}
