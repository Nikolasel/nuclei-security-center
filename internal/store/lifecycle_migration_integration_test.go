package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestGlobalFindingIdentityMigrationPostgres starts at the pre-0030 schema so
// it exercises the data migration, not merely fresh-schema ingestion. It covers
// both directions: one collided lifecycle splits into result variants, and the
// same variant from different targets merges into one global lifecycle.
func TestGlobalFindingIdentityMigrationPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Reproduce the real upgrade path: an early revision of PR #151 shipped
	// 0029 with only this index, and existing databases recorded that filename
	// before the migration later gained last_covering_scan. The migration runner
	// will not replay an already-recorded filename.
	st := openIsolatedPostgres(t, ctx, dsn, "0028_finding_raw_line.sql")
	if _, err := st.pool.Exec(ctx,
		`CREATE INDEX IF NOT EXISTS scans_complete_target_created_idx
		    ON scans (target_id, created_at DESC)
		    WHERE state = 'complete'`); err != nil {
		t.Fatalf("apply historical 0029 body: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ('0029_template_aware_lifecycle.sql')`); err != nil {
		t.Fatalf("record historical 0029: %v", err)
	}

	targetA := types.NewID()
	targetB := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts) VALUES
		     ($1, 'migration-a', ARRAY['same.invalid']),
		     ($2, 'migration-b', ARRAY['same.invalid'])`,
		targetA, targetB); err != nil {
		t.Fatalf("insert targets: %v", err)
	}

	scanA := types.NewID()
	scanB := types.NewID()
	baseTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	spec := `{"targets":["same.invalid"],"templates":{"template_ids":["tls-version"]}}`
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO scans (id, state, spec, target_id, created_at, finished_at) VALUES
		     ($1, 'complete', $3::jsonb, $2, $5, $5),
		     ($4, 'complete', $3::jsonb, $6, $7, $7)`,
		scanA, targetA, spec, scanB, baseTime, targetB, baseTime.Add(time.Minute)); err != nil {
		t.Fatalf("insert scans: %v", err)
	}

	oldKeyA := targetA + dedupSep + "tls-version" + dedupSep + "same.invalid:443"
	oldKeyB := targetB + dedupSep + "tls-version" + dedupSep + "same.invalid:443"
	var lifecycleA, lifecycleB, lifecycleC int64
	if err := st.pool.QueryRow(ctx,
		`INSERT INTO finding_lifecycle
		     (dedup_key, target_id, template_id, name, severity, host, matched_at, type,
		      first_seen_scan, last_seen_scan, first_seen_at, last_seen_at,
		      disposition, disposition_note, disposition_by, disposition_at,
		      recast_severity, recast_note, recast_by, recast_at)
		 VALUES
		     ($1, $2, 'tls-version', 'TLS version', 'info', 'same.invalid',
		      'same.invalid:443', 'ssl', $3, $3, $4, $4,
		      'accepted', 'keep accepted', 'analyst-a', $5,
		      'high', 'raise', 'analyst-a', $6)
		 RETURNING id`,
		oldKeyA, targetA, scanA, baseTime, baseTime.Add(4*time.Minute), baseTime.Add(time.Minute),
	).Scan(&lifecycleA); err != nil {
		t.Fatalf("insert lifecycle A: %v", err)
	}
	if err := st.pool.QueryRow(ctx,
		`INSERT INTO finding_lifecycle
		     (dedup_key, target_id, template_id, name, severity, host, matched_at, type,
		      first_seen_scan, last_seen_scan, first_seen_at, last_seen_at,
		      disposition, disposition_note, disposition_by, disposition_at,
		      recast_severity, recast_note, recast_by, recast_at)
		 VALUES
		     ($1, $2, 'tls-version', 'TLS version', 'info', 'same.invalid',
		      'same.invalid:443', 'ssl', $3, $3, $4, $4,
		      'false_positive', 'older disposition', 'analyst-b', $5,
		      NULL, 'explicit clear', 'analyst-b', $6)
		 RETURNING id`,
		oldKeyB, targetB, scanB, baseTime.Add(time.Minute), baseTime.Add(2*time.Minute), baseTime.Add(5*time.Minute),
	).Scan(&lifecycleB); err != nil {
		t.Fatalf("insert lifecycle B: %v", err)
	}
	matchedC1 := "https://same.invalid/\u0085status"
	oldKeyC := targetA + dedupSep + "c1-template" + dedupSep + matchedC1
	if err := st.pool.QueryRow(ctx,
		`INSERT INTO finding_lifecycle
		     (dedup_key, target_id, template_id, name, severity, host, matched_at, type,
		      first_seen_scan, last_seen_scan, first_seen_at, last_seen_at)
		 VALUES ($1, $2, 'c1-template', 'C1 identity', 'low', 'same.invalid',
		         $3, 'http', $4, $4, $5, $5)
		 RETURNING id`,
		oldKeyC, targetA, matchedC1, scanA, baseTime,
	).Scan(&lifecycleC); err != nil {
		t.Fatalf("insert 1:1 lifecycle: %v", err)
	}

	rawTLS12 := `{"template-id":"tls-version","matched-at":"same.invalid:443","extracted-results":["tls12"],"timestamp":"volatile-a"}`
	rawTLS13 := `{"template-id":"tls-version","matched-at":"same.invalid:443","extracted-results":["tls13"],"timestamp":"volatile-b"}`
	insertOccurrence := func(scanID, targetID, oldKey, raw string, lifecycleID int64, at time.Time) int64 {
		t.Helper()
		var id int64
		if err := st.pool.QueryRow(ctx,
			`INSERT INTO findings
			     (scan_id, target_id, dedup_key, finding_id, template_id, name, severity,
			      host, matched_at, type, cve, tags, raw, raw_line, created_at)
			 VALUES ($1, $2, $3, $4, 'tls-version', 'TLS version', 'info',
			         'same.invalid', 'same.invalid:443', 'ssl', '{}', '{}', $5::jsonb, $5, $6)
			 RETURNING id`,
			scanID, targetID, oldKey, lifecycleID, raw, at).Scan(&id); err != nil {
			t.Fatalf("insert occurrence: %v", err)
		}
		return id
	}
	occA12 := insertOccurrence(scanA, targetA, oldKeyA, rawTLS12, lifecycleA, baseTime)
	occA13 := insertOccurrence(scanA, targetA, oldKeyA, rawTLS13, lifecycleA, baseTime.Add(time.Second))
	occB12 := insertOccurrence(scanB, targetB, oldKeyB, rawTLS12, lifecycleB, baseTime.Add(time.Minute))
	rawC, err := json.Marshal(map[string]any{
		"template-id": "c1-template",
		"matched-at":  matchedC1,
	})
	if err != nil {
		t.Fatalf("marshal C1 occurrence: %v", err)
	}
	var occC int64
	if err := st.pool.QueryRow(ctx,
		`INSERT INTO findings
		     (scan_id, target_id, dedup_key, finding_id, template_id, name, severity,
		      host, matched_at, type, cve, tags, raw, raw_line, created_at)
		 VALUES ($1, $2, $3, $4, 'c1-template', 'C1 identity', 'low',
		         'same.invalid', $5, 'http', '{}', '{}', $6::jsonb, $6, $7)
		 RETURNING id`,
		scanA, targetA, oldKeyC, lifecycleC, matchedC1, rawC, baseTime.Add(2*time.Second),
	).Scan(&occC); err != nil {
		t.Fatalf("insert 1:1 occurrence: %v", err)
	}
	ghostKey := targetA + dedupSep + "deleted-template" + dedupSep + "https://same.invalid/ghost"
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO findings
		     (scan_id, target_id, dedup_key, finding_id, template_id, name, severity,
		      host, matched_at, type, cve, tags, raw, raw_line, created_at)
		 VALUES ($1, $2, $3, NULL, 'deleted-template', 'Deleted lifecycle', 'low',
		         'same.invalid', 'https://same.invalid/ghost', 'http', '{}', '{}',
		         '{"template-id":"deleted-template"}'::jsonb,
		         '{"template-id":"deleted-template"}', $4)`,
		scanA, targetA, ghostKey, baseTime.Add(3*time.Second)); err != nil {
		t.Fatalf("insert deliberately unlinked occurrence: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`UPDATE finding_lifecycle SET latest_occurrence_id = $1 WHERE id = $2`,
		occA13, lifecycleA); err != nil {
		t.Fatalf("set old latest occurrence A: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`UPDATE finding_lifecycle SET latest_occurrence_id = $1 WHERE id = $2`,
		occB12, lifecycleB); err != nil {
		t.Fatalf("set old latest occurrence B: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`UPDATE finding_lifecycle SET latest_occurrence_id = $1 WHERE id = $2`,
		occC, lifecycleC); err != nil {
		t.Fatalf("set old latest occurrence C: %v", err)
	}

	// Exercise the real runner: it must skip the already-recorded drifted 0029,
	// apply the separately named repair, and then apply the global migration.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate drifted 0029 schema: %v", err)
	}

	var scansIndexDefinition string
	if err := st.pool.QueryRow(ctx,
		`SELECT indexdef FROM pg_indexes
		  WHERE schemaname = current_schema()
		    AND indexname = 'scans_complete_target_created_idx'`,
	).Scan(&scansIndexDefinition); err != nil {
		t.Fatalf("read repaired scan index: %v", err)
	}
	if strings.Contains(scansIndexDefinition, "created_at DESC") {
		t.Fatalf("drifted scan index did not converge: %s", scansIndexDefinition)
	}

	rows, err := st.pool.Query(ctx,
		`SELECT id, dedup_key, result_discriminator, template_id, disposition, disposition_by,
		        recast_severity, recast_by,
		        ARRAY(
		            SELECT DISTINCT target_id::text
		              FROM findings
		             WHERE finding_id = finding_lifecycle.id
		             ORDER BY target_id::text
		        )
		   FROM finding_lifecycle
		  ORDER BY result_discriminator`)
	if err != nil {
		t.Fatalf("list migrated lifecycle: %v", err)
	}
	defer rows.Close()

	type migrated struct {
		id             int64
		dedupKey       string
		discriminator  string
		templateID     string
		disposition    string
		dispositionBy  string
		recastSeverity *string
		recastBy       string
		targetIDs      []string
	}
	var migratedRows []migrated
	for rows.Next() {
		var row migrated
		var dispositionBy, recastBy *string
		if err := rows.Scan(&row.id, &row.dedupKey, &row.discriminator, &row.templateID,
			&row.disposition, &dispositionBy,
			&row.recastSeverity, &recastBy, &row.targetIDs); err != nil {
			t.Fatalf("scan migrated lifecycle: %v", err)
		}
		row.dispositionBy = deref(dispositionBy)
		row.recastBy = deref(recastBy)
		migratedRows = append(migratedRows, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migrated lifecycle: %v", err)
	}
	if len(migratedRows) != 3 {
		t.Fatalf("migrated lifecycle rows = %d, want 3", len(migratedRows))
	}

	discriminator12, err := resultDiscriminator([]byte(rawTLS12))
	if err != nil {
		t.Fatalf("derive tls12 discriminator: %v", err)
	}
	discriminator13, err := resultDiscriminator([]byte(rawTLS13))
	if err != nil {
		t.Fatalf("derive tls13 discriminator: %v", err)
	}
	byDiscriminator := map[string]migrated{}
	byTemplate := map[string]migrated{}
	for _, row := range migratedRows {
		byDiscriminator[row.discriminator] = row
		byTemplate[row.templateID] = row
	}
	tls12, ok := byDiscriminator[discriminator12]
	if !ok {
		t.Fatalf("TLS 1.2 lifecycle missing: %#v", migratedRows)
	}
	tls13, ok := byDiscriminator[discriminator13]
	if !ok {
		t.Fatalf("TLS 1.3 lifecycle missing: %#v", migratedRows)
	}
	if tls12.disposition != "accepted" || tls12.dispositionBy != "analyst-a" {
		t.Fatalf("TLS 1.2 disposition = %s/%s, want newest accepted/analyst-a",
			tls12.disposition, tls12.dispositionBy)
	}
	if tls12.recastSeverity != nil || tls12.recastBy != "analyst-b" {
		t.Fatalf("TLS 1.2 recast = %v/%s, want newest explicit clear/analyst-b",
			tls12.recastSeverity, tls12.recastBy)
	}
	wantTLS12Targets := []string{targetA, targetB}
	sort.Strings(wantTLS12Targets)
	if fmt.Sprint(tls12.targetIDs) != fmt.Sprint(wantTLS12Targets) {
		t.Fatalf("TLS 1.2 targets = %v, want both targets", tls12.targetIDs)
	}
	if tls13.disposition != "accepted" || tls13.recastSeverity == nil ||
		*tls13.recastSeverity != "high" || fmt.Sprint(tls13.targetIDs) != fmt.Sprint([]string{targetA}) {
		t.Fatalf("TLS 1.3 analyst state/provenance = %#v", tls13)
	}
	ordinary := byTemplate["c1-template"]
	if ordinary.id != lifecycleC {
		t.Fatalf("1:1 lifecycle id = %d, want preserved id %d", ordinary.id, lifecycleC)
	}
	if ordinary.dedupKey != DedupKey("c1-template", matchedC1, "") {
		t.Fatalf("C1 lifecycle key = %q, want Go key %q",
			ordinary.dedupKey, DedupKey("c1-template", matchedC1, ""))
	}

	var linked12, linked13 int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE finding_id = $1),
		        count(*) FILTER (WHERE finding_id = $2)
		   FROM findings`,
		tls12.id, tls13.id).Scan(&linked12, &linked13); err != nil {
		t.Fatalf("count migrated occurrence links: %v", err)
	}
	if linked12 != 2 || linked13 != 1 {
		t.Fatalf("migrated occurrence links = tls12:%d tls13:%d, want 2/1", linked12, linked13)
	}

	var ghostLifecycleCount int
	var ghostFindingID *int64
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM finding_lifecycle WHERE template_id = 'deleted-template'`,
	).Scan(&ghostLifecycleCount); err != nil {
		t.Fatalf("count resurrected lifecycle rows: %v", err)
	}
	if err := st.pool.QueryRow(ctx,
		`SELECT finding_id FROM findings WHERE template_id = 'deleted-template'`,
	).Scan(&ghostFindingID); err != nil {
		t.Fatalf("read deliberately unlinked occurrence: %v", err)
	}
	if ghostLifecycleCount != 0 || ghostFindingID != nil {
		t.Fatalf("deleted lifecycle resurrected: lifecycle_count=%d finding_id=%v",
			ghostLifecycleCount, ghostFindingID)
	}

	var helperCount int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*)
		   FROM pg_proc
		  WHERE oid IN (
		      to_regprocedure('nsc_finding_result_discriminator(jsonb)'),
		      to_regprocedure('nsc_finding_key_part(text)')
		  )`,
	).Scan(&helperCount); err != nil {
		t.Fatalf("check migration helper cleanup: %v", err)
	}
	if helperCount != 0 {
		t.Fatalf("migration left %d helper functions behind", helperCount)
	}

	_ = occA12 // documents that all three original occurrence ids remain immutable.
}

// TestGlobalFindingIdentityMigrationFromFinal0029Postgres covers the other
// supported upgrade state: the final 0029 body was applied in full. The repair
// migration must remain harmless and converge to the same schema.
func TestGlobalFindingIdentityMigrationFromFinal0029Postgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn, "0029_template_aware_lifecycle.sql")

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate final 0029 schema: %v", err)
	}

	var hasResultDiscriminator, hasTargetID bool
	if err := st.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			 WHERE table_schema = current_schema()
			   AND table_name = 'finding_lifecycle'
			   AND column_name = 'result_discriminator'
		), EXISTS (
			SELECT 1 FROM information_schema.columns
			 WHERE table_schema = current_schema()
			   AND table_name = 'finding_lifecycle'
			   AND column_name = 'target_id'
		)`,
	).Scan(&hasResultDiscriminator, &hasTargetID); err != nil {
		t.Fatalf("inspect migrated lifecycle schema: %v", err)
	}
	if !hasResultDiscriminator || hasTargetID {
		t.Fatalf("unexpected final lifecycle schema: result_discriminator=%t target_id=%t",
			hasResultDiscriminator, hasTargetID)
	}

	var scansIndexDefinition string
	if err := st.pool.QueryRow(ctx,
		`SELECT indexdef FROM pg_indexes
		  WHERE schemaname = current_schema()
		    AND indexname = 'scans_complete_target_created_idx'`,
	).Scan(&scansIndexDefinition); err != nil {
		t.Fatalf("read converged scan index: %v", err)
	}
	if strings.Contains(scansIndexDefinition, "created_at DESC") {
		t.Fatalf("final-0029 scan index did not converge: %s", scansIndexDefinition)
	}

	if _, err := st.pool.Exec(ctx,
		`UPDATE schema_migrations
		    SET checksum_sha256 = 'tampered'
		  WHERE version = '0030_global_finding_identity.sql'`,
	); err != nil {
		t.Fatalf("tamper migration checksum: %v", err)
	}
	err := st.Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Migrate after checksum drift = %v, want checksum mismatch", err)
	}
}

func TestOccurrenceScanScopeConstraintPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn, "9999")

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
		t.Fatalf("target deletion scopes = scan:%v occurrence:%v, want both NULL",
			scanTarget, occurrenceTarget)
	}
}

func TestOccurrenceScanScopeUpgradePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn, "0031_finalize_global_finding_identity.sql")

	targetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts)
		 VALUES ($1, 'deleted-before-scope-constraint', ARRAY['deleted.invalid'])`,
		targetID,
	); err != nil {
		t.Fatalf("insert pre-0032 target: %v", err)
	}
	scanID, err := st.CreateScan(ctx, types.ScanSpec{}, ScanLink{TargetID: targetID})
	if err != nil {
		t.Fatalf("create pre-0032 targeted scan: %v", err)
	}
	var occurrenceID int64
	if err := st.pool.QueryRow(ctx,
		`INSERT INTO findings (scan_id, target_id, dedup_key, template_id, raw)
		 VALUES ($1, $2, 'pre-0032-deleted-target', 'scope-upgrade-test', '{}'::jsonb)
		 RETURNING id`,
		scanID, targetID,
	).Scan(&occurrenceID); err != nil {
		t.Fatalf("insert pre-0032 occurrence: %v", err)
	}
	if err := st.DeleteTarget(ctx, targetID); err != nil {
		t.Fatalf("delete target before 0032: %v", err)
	}

	var mismatches int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*)
		   FROM findings occurrence
		   JOIN scans observed_scan ON observed_scan.id = occurrence.scan_id
		  WHERE occurrence.target_id IS DISTINCT FROM observed_scan.target_id`,
	).Scan(&mismatches); err != nil {
		t.Fatalf("count pre-0032 scope mismatches: %v", err)
	}
	if mismatches != 1 {
		t.Fatalf("pre-0032 scope mismatches = %d, want 1", mismatches)
	}

	// Drive the real runner so lexical ordering and the recorded 0031 boundary
	// are covered: 0031a must repair the row before 0032 adds its FK.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("upgrade deleted-target history through 0032: %v", err)
	}
	var scanTarget, occurrenceTarget *string
	if err := st.pool.QueryRow(ctx,
		`SELECT scans.target_id::text, findings.target_id::text
		   FROM scans
		   JOIN findings ON findings.scan_id = scans.id
		  WHERE findings.id = $1`,
		occurrenceID,
	).Scan(&scanTarget, &occurrenceTarget); err != nil {
		t.Fatalf("read repaired historical scope: %v", err)
	}
	if scanTarget != nil || occurrenceTarget != nil {
		t.Fatalf("repaired historical scopes = scan:%v occurrence:%v, want both NULL",
			scanTarget, occurrenceTarget)
	}
}

func applyMigrationsThrough(t *testing.T, ctx context.Context, st *Store, last string) {
	t.Helper()
	if _, err := st.pool.Exec(ctx, `
		CREATE TABLE schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create schema migrations table: %v", err)
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() <= last {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		applyMigration(t, ctx, st, name)
	}
}

func openIsolatedPostgres(t *testing.T, ctx context.Context, dsn, lastMigration string) *Store {
	t.Helper()
	admin, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin store: %v", err)
	}
	t.Cleanup(admin.Close)

	schema := "nsc_test_" + strings.ReplaceAll(types.NewID(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test database url: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open isolated schema pool: %v", err)
	}
	t.Cleanup(pool.Close)
	st := &Store{pool: pool}
	applyMigrationsThrough(t, ctx, st, lastMigration)
	return st
}

func applyMigration(t *testing.T, ctx context.Context, st *Store, name string) {
	t.Helper()
	sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	if _, err := st.pool.Exec(ctx, string(sqlBytes)); err != nil {
		t.Fatalf("apply migration %s: %v", name, err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
		t.Fatalf("record migration %s: %v", name, err)
	}
}
