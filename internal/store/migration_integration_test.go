package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

//go:embed testdata/alpha_migrations/*.sql
var alphaMigrationsFS embed.FS

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

func TestAlphaMigrationFixtureIntegrity(t *testing.T) {
	names, err := fs.Glob(alphaMigrationsFS, "testdata/alpha_migrations/*.sql")
	if err != nil {
		t.Fatalf("list alpha migration fixtures: %v", err)
	}
	sort.Strings(names)
	if len(names) != 44 {
		t.Fatalf("alpha migration fixture count = %d, want 44", len(names))
	}

	digest := sha256.New()
	for _, fullName := range names {
		name := strings.TrimPrefix(fullName, "testdata/alpha_migrations/")
		body, err := alphaMigrationsFS.ReadFile(fullName)
		if err != nil {
			t.Fatalf("read alpha migration fixture %s: %v", name, err)
		}
		_, _ = digest.Write([]byte(name))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(body)
		_, _ = digest.Write([]byte{0})
	}

	const want = "cffa9ca24c5ce0b0f807a777898049a470b04d7d380c0db28eca10dacc8874c5"
	if got := fmt.Sprintf("%x", digest.Sum(nil)); got != want {
		t.Fatalf("alpha migration fixture digest = %s, want %s; update the pin only for an intentional pre-beta reference-chain change", got, want)
	}
}

func TestMigrateRejectsUnknownAppliedVersionPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, _ := openEmptyIsolatedPostgres(t, ctx, dsn)

	const legacyVersion = "0002_scanner_node_capacity.sql"
	if _, err := st.pool.Exec(ctx, `
		CREATE TABLE schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create unsupported migration history: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1)`, legacyVersion); err != nil {
		t.Fatalf("record unsupported migration: %v", err)
	}

	err := st.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted a database with an unsupported applied migration")
	}
	if !strings.Contains(err.Error(), legacyVersion) ||
		!strings.Contains(err.Error(), "current fresh-deployment baseline") ||
		!strings.Contains(err.Error(), "new empty database") {
		t.Fatalf("Migrate error = %q, want legacy version and fresh-deploy guidance", err)
	}
	var checksumColumnAdded bool
	if err := st.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM information_schema.columns
			 WHERE table_schema = current_schema()
			   AND table_name = 'schema_migrations'
			   AND column_name = 'checksum_sha256'
		)`).Scan(&checksumColumnAdded); err != nil {
		t.Fatalf("inspect rejected migration history: %v", err)
	}
	if checksumColumnAdded {
		t.Fatal("Migrate altered migration history before rejecting it")
	}
	var baselineApplied bool
	if err := st.pool.QueryRow(ctx, `SELECT to_regclass('app_settings') IS NOT NULL`).Scan(&baselineApplied); err != nil {
		t.Fatalf("check for partially applied baseline: %v", err)
	}
	if baselineApplied {
		t.Fatal("Migrate partially applied the baseline before rejecting unsupported history")
	}
}

func TestMigrateRejectsMissingChecksumPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)
	if _, err := st.pool.Exec(ctx,
		`UPDATE schema_migrations SET checksum_sha256 = NULL WHERE version = '0001_init.sql'`); err != nil {
		t.Fatalf("clear baseline checksum: %v", err)
	}

	err := st.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted an applied migration without a checksum")
	}
	if !strings.Contains(err.Error(), "has no recorded checksum") ||
		!strings.Contains(err.Error(), "current fresh-deployment baseline") ||
		!strings.Contains(err.Error(), "new empty database") {
		t.Fatalf("Migrate error = %q, want missing-checksum and fresh-deploy guidance", err)
	}
}

func TestMigrateRejectsLegacyHistoryWithoutChecksumColumnBeforeMutationPostgres(t *testing.T) {
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
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		INSERT INTO schema_migrations (version) VALUES ('0001_init.sql');
	`); err != nil {
		t.Fatalf("seed legacy migration history: %v", err)
	}

	err := st.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted legacy history without a checksum column")
	}

	var checksumColumnAdded bool
	if err := st.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM information_schema.columns
			 WHERE table_schema = current_schema()
			   AND table_name = 'schema_migrations'
			   AND column_name = 'checksum_sha256'
		)`).Scan(&checksumColumnAdded); err != nil {
		t.Fatalf("inspect rejected legacy migration history: %v", err)
	}
	if checksumColumnAdded {
		t.Fatal("Migrate altered legacy migration history before rejecting it")
	}
	if !strings.Contains(err.Error(), "has no checksum column") ||
		!strings.Contains(err.Error(), "current fresh-deployment baseline") ||
		!strings.Contains(err.Error(), "new empty database") {
		t.Fatalf("Migrate error = %q, want missing-column and fresh-deploy guidance", err)
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
		!strings.Contains(err.Error(), "changed since this database was created") ||
		!strings.Contains(err.Error(), "current fresh-deployment baseline") ||
		!strings.Contains(err.Error(), "new empty database") ||
		!strings.Contains(err.Error(), "recorded tampered") {
		t.Fatalf("Migrate error = %q, want checksum-mismatch and fresh-deploy guidance", err)
	}
	if strings.Contains(err.Error(), "applied migrations are immutable") {
		t.Fatalf("Migrate error = %q, want alpha baseline-change guidance instead of post-beta immutability guidance", err)
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
	st, _ := openEmptyIsolatedPostgresWithRuntimeParams(t, ctx, dsn, map[string]string{
		"statement_timeout": "100ms",
	})
	if _, err := st.pool.Exec(ctx, `
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

func TestBaselineMatchesAlphaChainPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	pgDump := findPGDump(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alpha, alphaSchema := openEmptyIsolatedPostgres(t, ctx, dsn)
	baseline, baselineSchema := openEmptyIsolatedPostgres(t, ctx, dsn)

	applySQLFiles(t, ctx, alpha, alphaMigrationsFS, "testdata/alpha_migrations")
	baselineSQL, err := migrationsFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("read consolidated baseline: %v", err)
	}
	if _, err := baseline.pool.Exec(ctx, string(baselineSQL)); err != nil {
		t.Fatalf("apply consolidated baseline: %v", err)
	}

	alphaDump := normalizedSchemaDump(t, ctx, pgDump, dsn, alphaSchema)
	baselineDump := normalizedSchemaDump(t, ctx, pgDump, dsn, baselineSchema)
	if alphaDump != baselineDump {
		t.Fatalf("consolidated baseline differs from the alpha migration chain: %s", firstSchemaDifference(alphaDump, baselineDump))
	}
	alphaState := readInitialApplicationState(t, ctx, alpha)
	baselineState := readInitialApplicationState(t, ctx, baseline)
	if fmt.Sprint(alphaState) != fmt.Sprint(baselineState) {
		t.Fatalf("consolidated baseline initial state = %#v, want alpha-chain state %#v", baselineState, alphaState)
	}
}

type initialApplicationState struct {
	appSettingsRows         int
	templateSets            []string
	findingsSequence        int64
	findingsSequenceCalled  bool
	lifecycleSequence       int64
	lifecycleSequenceCalled bool
}

func readInitialApplicationState(t *testing.T, ctx context.Context, st *Store) initialApplicationState {
	t.Helper()
	var state initialApplicationState
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM app_settings`).Scan(&state.appSettingsRows); err != nil {
		t.Fatalf("count initial app settings: %v", err)
	}
	if err := st.pool.QueryRow(ctx, `
		SELECT coalesce(array_agg(name || ':' || mode ORDER BY name), ARRAY[]::text[])
		  FROM template_sets
	`).Scan(&state.templateSets); err != nil {
		t.Fatalf("read initial template sets: %v", err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT last_value, is_called FROM findings_id_seq`).
		Scan(&state.findingsSequence, &state.findingsSequenceCalled); err != nil {
		t.Fatalf("read initial findings sequence: %v", err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT last_value, is_called FROM finding_lifecycle_id_seq`).
		Scan(&state.lifecycleSequence, &state.lifecycleSequenceCalled); err != nil {
		t.Fatalf("read initial lifecycle sequence: %v", err)
	}
	return state
}

func applySQLFiles(t *testing.T, ctx context.Context, st *Store, source fs.FS, dir string) {
	t.Helper()
	entries, err := fs.ReadDir(source, dir)
	if err != nil {
		t.Fatalf("read SQL fixtures: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		sqlBytes, err := fs.ReadFile(source, dir+"/"+name)
		if err != nil {
			t.Fatalf("read SQL fixture %s: %v", name, err)
		}
		if _, err := st.pool.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply SQL fixture %s: %v", name, err)
		}
	}
}

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

func firstSchemaDifference(alpha, baseline string) string {
	alphaLines := strings.Split(alpha, "\n")
	baselineLines := strings.Split(baseline, "\n")
	maxLines := max(len(alphaLines), len(baselineLines))
	for i := 0; i < maxLines; i++ {
		var alphaLine, baselineLine string
		if i < len(alphaLines) {
			alphaLine = alphaLines[i]
		}
		if i < len(baselineLines) {
			baselineLine = baselineLines[i]
		}
		if alphaLine != baselineLine {
			return fmt.Sprintf("first difference at line %d\nalpha:    %q\nbaseline: %q", i+1, alphaLine, baselineLine)
		}
	}
	return "dumps have different bytes but no differing lines"
}
