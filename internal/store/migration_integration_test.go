package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func currentMigrationCount(t *testing.T) int {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("list embedded migrations: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count
}

func TestMigrateRejectsUnknownAppliedVersionPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, _ := openEmptyIsolatedPostgres(t, ctx, dsn)

	const newerVersion = "0099_future_release.sql"
	if _, err := st.pool.Exec(ctx, `
		CREATE TABLE schema_migrations (
			version TEXT PRIMARY KEY,
			checksum_sha256 TEXT,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create unsupported migration history: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO schema_migrations (version, checksum_sha256) VALUES ($1, $2)`,
		newerVersion, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("record unsupported migration: %v", err)
	}

	err := st.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted a database with an unsupported applied migration")
	}
	if !strings.Contains(err.Error(), newerVersion) ||
		!strings.Contains(err.Error(), "migrated by a newer release") ||
		!strings.Contains(err.Error(), "run that release or newer") {
		t.Fatalf("Migrate error = %q, want unknown version and newer-release guidance", err)
	}
	var baselineApplied bool
	if err := st.pool.QueryRow(ctx, `SELECT to_regclass('app_settings') IS NOT NULL`).Scan(&baselineApplied); err != nil {
		t.Fatalf("check for partially applied baseline: %v", err)
	}
	if baselineApplied {
		t.Fatal("Migrate partially applied the baseline before rejecting unsupported history")
	}
}

func TestMigrateRejectsChecksumMismatchPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)
	if _, err := st.pool.Exec(ctx,
		`UPDATE schema_migrations SET checksum_sha256 = 'tampered' WHERE version = '0001_init.sql'`); err != nil {
		t.Fatalf("alter baseline checksum: %v", err)
	}

	err := st.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted a changed applied migration")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") ||
		!strings.Contains(err.Error(), "applied migrations are immutable") ||
		!strings.Contains(err.Error(), "new numbered forward migration") ||
		!strings.Contains(err.Error(), "recorded tampered") {
		t.Fatalf("Migrate error = %q, want checksum-mismatch and immutability guidance", err)
	}
	if strings.Contains(err.Error(), "newer release") {
		t.Fatalf("Migrate error = %q, want immutability guidance instead of newer-release history guidance", err)
	}
}

func TestBaselineSeedsAppSettingsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)
	settings, err := st.GetAppSettings(ctx)
	if err != nil {
		t.Fatalf("read baseline app settings: %v", err)
	}
	if settings.RetentionEnabled || settings.ScanRetentionDays != nil || settings.RetentionIncludeAdhoc {
		t.Fatalf("baseline app settings = %#v, want retention disabled with no retention days", settings)
	}
}

func TestMigrateIndexesScanDeletionFKCleanupColumnsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	// These columns carry ON DELETE SET NULL foreign keys, so deleting scans
	// (manual deletes and retention sweeps cascading through findings and
	// schedules) runs one referential-integrity UPDATE against the referencing
	// table per deleted row. A valid non-partial btree index keyed on each
	// column keeps those updates off full seq scans. Full indexes are a choice
	// of simplicity and write-cost, not a requirement: the planner also picks
	// IS NOT NULL partial indexes for the cached RI plan (the schema already
	// relies on that for finding_lifecycle_last_covering_scan_idx), but nearly
	// every row holds a non-NULL pointer here, so a partial variant would save
	// nothing.
	for _, tc := range []struct{ table, column string }{
		{"finding_lifecycle", "latest_occurrence_id"},
		{"schedules", "last_scan_id"},
	} {
		t.Run(tc.table+"."+tc.column, func(t *testing.T) {
			var indexes int
			if err := st.pool.QueryRow(ctx, `
				SELECT count(*)
				  FROM pg_index i
				  JOIN pg_class tbl ON tbl.oid = i.indrelid
				  JOIN pg_class idx ON idx.oid = i.indexrelid
				  JOIN pg_am am ON am.oid = idx.relam
				 WHERE tbl.relnamespace = current_schema()::regnamespace
				   AND tbl.relname = $1
				   AND i.indisvalid
				   AND i.indpred IS NULL
				   AND am.amname = 'btree'
				   AND pg_get_indexdef(i.indexrelid, 1, true) = $2`,
				tc.table, tc.column,
			).Scan(&indexes); err != nil {
				t.Fatalf("inspect scan-deletion FK-cleanup indexes: %v", err)
			}
			if indexes == 0 {
				t.Fatalf("no valid non-partial btree index on %s.%s; scan deletion loses its FK-cleanup index", tc.table, tc.column)
			}
		})
	}
}

func TestScannerNodeCapacityDefaultsAndPersistsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	node, err := st.CreateScannerNode(ctx, ScannerNode{
		Name:     fmt.Sprintf("capacity-%d", time.Now().UnixNano()),
		Endpoint: "http://scanner:8081",
		Token:    "test-token",
	})
	if err != nil {
		t.Fatalf("create scanner node: %v", err)
	}
	if node.MaxConcurrentScans != 20 {
		t.Fatalf("created node max_concurrent_scans = %d, want default 20", node.MaxConcurrentScans)
	}

	node.MaxConcurrentScans = 3
	node.Token = ""
	updated, err := st.UpdateScannerNode(ctx, node.ID, node)
	if err != nil {
		t.Fatalf("update scanner node capacity: %v", err)
	}
	if updated.MaxConcurrentScans != 3 {
		t.Fatalf("updated node max_concurrent_scans = %d, want 3", updated.MaxConcurrentScans)
	}

	got, err := st.GetScannerNode(ctx, node.ID)
	if err != nil {
		t.Fatalf("read scanner node: %v", err)
	}
	if got.MaxConcurrentScans != 3 {
		t.Fatalf("persisted node max_concurrent_scans = %d, want 3", got.MaxConcurrentScans)
	}
}

func TestBaselineRecordsChecksumAndIsIdempotentPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	var beforeChecksum string
	var beforeCount int
	if err := st.pool.QueryRow(ctx, `
		SELECT min(checksum_sha256), count(*)
		  FROM schema_migrations
		 WHERE version = '0001_init.sql'`).Scan(&beforeChecksum, &beforeCount); err != nil {
		t.Fatalf("read baseline migration record: %v", err)
	}
	if beforeCount != 1 || len(beforeChecksum) != sha256.Size*2 {
		t.Fatalf("baseline migration record = count %d checksum %q, want one SHA-256 checksum", beforeCount, beforeChecksum)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate call: %v", err)
	}
	var afterChecksum string
	var afterCount int
	if err := st.pool.QueryRow(ctx, `
		SELECT min(checksum_sha256), count(*)
		  FROM schema_migrations
		 WHERE version = '0001_init.sql'`).Scan(&afterChecksum, &afterCount); err != nil {
		t.Fatalf("read idempotent migration record: %v", err)
	}
	if afterCount != beforeCount || afterChecksum != beforeChecksum {
		t.Fatalf("second Migrate changed migration record: before=(%d,%q) after=(%d,%q)", beforeCount, beforeChecksum, afterCount, afterChecksum)
	}
}

func TestMigrateRollsBackSQLWhenHistoryRecordFailsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, _ := openEmptyIsolatedPostgres(t, ctx, dsn)
	if _, err := st.pool.Exec(ctx, `
		CREATE TABLE schema_migrations (
			version TEXT PRIMARY KEY,
			checksum_sha256 TEXT,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE FUNCTION reject_migration_record() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'forced migration history failure';
		END;
		$$;
		CREATE TRIGGER reject_migration_record
			BEFORE INSERT ON schema_migrations
			FOR EACH ROW EXECUTE FUNCTION reject_migration_record();
	`); err != nil {
		t.Fatalf("install migration history failure trigger: %v", err)
	}

	err := st.Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "record migration 0001_init.sql") {
		t.Fatalf("Migrate error = %v, want forced history-record failure", err)
	}
	var baselineApplied bool
	if err := st.pool.QueryRow(ctx, `SELECT to_regclass('app_settings') IS NOT NULL`).Scan(&baselineApplied); err != nil {
		t.Fatalf("check migration rollback: %v", err)
	}
	if baselineApplied {
		t.Fatal("migration SQL remained applied after its history record failed")
	}

	if _, err := st.pool.Exec(ctx, `
		DROP TRIGGER reject_migration_record ON schema_migrations;
		DROP FUNCTION reject_migration_record();
	`); err != nil {
		t.Fatalf("remove migration history failure trigger: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate retry after rollback: %v", err)
	}
	var migrationCount int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("count migration records after retry: %v", err)
	}
	if want := currentMigrationCount(t); migrationCount != want {
		t.Fatalf("migration record count after retry = %d, want %d", migrationCount, want)
	}
}

func TestMigrateLiftsPoolStatementTimeoutForTransactionPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, schema := openEmptyIsolatedPostgresWithRuntimeParams(t, ctx, dsn, map[string]string{
		"statement_timeout": "100ms",
	})
	// Install the fixture over a dedicated connection without the pool's
	// statement_timeout: the 100ms budget is what Migrate must lift for its own
	// transaction, not a budget for test setup, whose DDL batch could otherwise
	// intermittently exceed it on loaded runners.
	setupCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse setup connection config: %v", err)
	}
	setupCfg.ConnConfig.RuntimeParams = map[string]string{"search_path": schema}
	setupPool, err := pgxpool.NewWithConfig(ctx, setupCfg)
	if err != nil {
		t.Fatalf("open setup pool: %v", err)
	}
	defer setupPool.Close()
	if _, err := setupPool.Exec(ctx, `
		CREATE TABLE schema_migrations (
			version TEXT PRIMARY KEY,
			checksum_sha256 TEXT,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE FUNCTION delay_migration_record_for_timeout() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(0.25);
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER delay_migration_record_for_timeout
			BEFORE INSERT ON schema_migrations
			FOR EACH ROW EXECUTE FUNCTION delay_migration_record_for_timeout();
	`); err != nil {
		t.Fatalf("install delayed migration history trigger: %v", err)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate with a delayed history record = %v, want timeout lifted locally", err)
	}

	var timeout string
	if err := st.pool.QueryRow(ctx, `SHOW statement_timeout`).Scan(&timeout); err != nil {
		t.Fatalf("read pool statement_timeout after migration: %v", err)
	}
	if timeout != "100ms" {
		t.Fatalf("pool statement_timeout after migration = %q, want 100ms", timeout)
	}
}

func TestMigrateWaitsForAdvisoryLockBeyondPoolStatementTimeoutPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, _ := openEmptyIsolatedPostgresWithRuntimeParams(t, ctx, dsn, map[string]string{
		"statement_timeout": "500ms",
	})
	lockTx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock holder transaction: %v", err)
	}
	defer func() { _ = lockTx.Rollback(ctx) }()
	if _, err := lockTx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtext(current_database()), hashtext(current_schema()))
	`); err != nil {
		t.Fatalf("acquire migration advisory lock: %v", err)
	}

	migrateErr := make(chan error, 1)
	go func() { migrateErr <- st.Migrate(ctx) }()

	waitCtx, waitCancel := context.WithTimeout(ctx, 2*time.Second)
	defer waitCancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := st.pool.QueryRow(waitCtx, `
			SELECT EXISTS (
				SELECT 1
				  FROM pg_locks
				 WHERE locktype = 'advisory' AND NOT granted
			)
		`).Scan(&waiting); err != nil {
			t.Fatalf("inspect migration lock wait: %v", err)
		}
		if waiting {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("Migrate did not reach the advisory lock wait: %v", waitCtx.Err())
		case <-ticker.C:
		}
	}

	// Keep the lock held beyond the pool timeout so the regression fails when
	// SET LOCAL is still placed after the advisory-lock statement.
	time.Sleep(750 * time.Millisecond)
	if err := lockTx.Commit(ctx); err != nil {
		t.Fatalf("release migration advisory lock: %v", err)
	}
	if err := <-migrateErr; err != nil {
		t.Fatalf("Migrate after waiting for the advisory lock = %v, want success", err)
	}
}

func TestMigrateSerializesConcurrentStartsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, _ := openEmptyIsolatedPostgres(t, ctx, dsn)
	if _, err := st.pool.Exec(ctx, `
		CREATE TABLE schema_migrations (
			version TEXT PRIMARY KEY,
			checksum_sha256 TEXT,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE FUNCTION delay_migration_record() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(0.25);
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER delay_migration_record
			BEFORE INSERT ON schema_migrations
			FOR EACH ROW EXECUTE FUNCTION delay_migration_record();
	`); err != nil {
		t.Fatalf("install migration history delay trigger: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			errs <- st.Migrate(ctx)
		}()
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Migrate: %v", err)
		}
	}

	var migrationCount int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("count migration records after concurrent starts: %v", err)
	}
	if want := currentMigrationCount(t); migrationCount != want {
		t.Fatalf("migration record count after concurrent starts = %d, want %d", migrationCount, want)
	}
}

// pg_dump helpers remain for later schema-upgrade tests.
func findPGDump(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("NSC_TEST_PG_DUMP"); configured != "" {
		return configured
	}
	if path, err := exec.LookPath("pg_dump"); err == nil {
		return path
	}
	for _, path := range []string{
		"/opt/homebrew/opt/libpq/bin/pg_dump",
		"/opt/homebrew/opt/postgresql@16/bin/pg_dump",
		"/usr/local/opt/libpq/bin/pg_dump",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	t.Fatal("NSC_TEST_DATABASE_URL is set but pg_dump was not found; install the PostgreSQL client or set NSC_TEST_PG_DUMP")
	return ""
}

func normalizedSchemaDump(t *testing.T, ctx context.Context, pgDump, dsn, schema string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, pgDump,
		"--schema-only",
		"--no-owner",
		"--no-privileges",
		"--schema="+schema,
		"--dbname="+dsn,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pg_dump schema %s: %v\n%s", schema, err, output)
	}

	lines := strings.Split(strings.ReplaceAll(string(output), schema, "nsc_schema"), "\n")
	normalized := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(line, `\restrict `) || strings.HasPrefix(line, `\unrestrict `) ||
			strings.HasPrefix(line, "-- Dumped from database version") ||
			strings.HasPrefix(line, "-- Dumped by pg_dump version") {
			continue
		}
		normalized = append(normalized, line)
	}
	return strings.Join(normalized, "\n")
}

func firstSchemaDifference(left, right string) string {
	leftLines := strings.Split(left, "\n")
	rightLines := strings.Split(right, "\n")
	maxLines := max(len(leftLines), len(rightLines))
	for i := 0; i < maxLines; i++ {
		var leftLine, rightLine string
		if i < len(leftLines) {
			leftLine = leftLines[i]
		}
		if i < len(rightLines) {
			rightLine = rightLines[i]
		}
		if leftLine != rightLine {
			return fmt.Sprintf("first difference at line %d\nleft:  %q\nright: %q", i+1, leftLine, rightLine)
		}
	}
	return "dumps have different bytes but no differing lines"
}
