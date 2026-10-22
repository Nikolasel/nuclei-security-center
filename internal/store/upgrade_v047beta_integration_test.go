package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// v047BetaCommit is the commit released as v0.4.7-beta (2026-10-03). The
// database below is built the way that release built it: its embedded
// migrations 0001 to 0005, applied and recorded like its Migrate did.
const v047BetaCommit = "2252888aeafbf4250dbfa6a09142c98396742e31"

// v047BetaMigrations are the migrations v0.4.7-beta shipped, with the SHA-256
// of each file at v047BetaCommit. The upgrade test applies the embedded copies,
// so they must still be byte-identical to the release.
var v047BetaMigrations = []struct{ name, checksum string }{
	{"0001_init.sql", "055c9e0422bf1b907601b68441b965e81653a3b14ea2ce8feb020c2b7827fc96"},
	{"0002_add_scan_policy_response_limits.sql", "61405adb7a97b09c18fb1e4b200600fefb2b44eb5a71f1e3c0a1635d3fa85ff0"},
	{"0003_finding_result_identity.sql", "53b687474cce5a7d5754d0d68dac90f648ce14bf11362fc065ccbb63e7f9d8a0"},
	{"0004_schedule_timezone.sql", "698ed0ab44f1e65fe725a61c7d39b218bac6b9a1f7bf53f32b6a3d9442bdfb04"},
	{"0005_scan_notification_outbox.sql", "6023690ceb7851c7095ba6531798407cbb8757becf70e39294a12041ebf4efb1"},
}

// columnsAddedSinceV047Beta states, per table, what the rows of a database
// upgraded from v0.4.7-beta hold in every column a later migration added, as
// the column's to_jsonb value. A column added with a default lists that
// default (for example `"UTC"`); a nullable column without one lists null. A
// new migration that adds a column to a table seeded below must add it here.
var columnsAddedSinceV047Beta = map[string]map[string]string{
	// 0006_template_sync_source.sql: seeded from the environment at startup,
	// never by the migration.
	"app_settings": {
		"template_sync_repo":              "null",
		"template_sync_ref":               "null",
		"template_sync_source_updated_at": "null",
		"template_sync_source_updated_by": "null",
	},
	// 0006_template_sync_source.sql: NULL marks pre-migration sync history.
	"template_sync_runs": {
		"restored":    "null",
		"source_repo": "null",
		"source_ref":  "null",
	},
}

// TestUpgradeFromV047BetaPostgres restores a v0.4.7-beta database dump, runs
// the current migrations on it and checks that the schema equals a fresh
// install and that every row it held reads back unchanged.
//
// The dump is generated here, not stored as a fixture: the v0.4.7-beta schema
// comes from this repository's migrations 0001 to 0005 (see v047BetaCommit),
// filled with synthetic seed data, dumped with pg_dump and restored with psql.
func TestUpgradeFromV047BetaPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	pgDump := findPGDump(t)
	psql := findPSQL(t, pgDump)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	release, schema := openEmptyIsolatedPostgres(t, ctx, dsn)
	applyV047BetaMigrations(t, ctx, release.pool)
	seedV047BetaData(t, ctx, release.pool)
	tables := schemaTables(t, ctx, release.pool)
	seeded := snapshotSchema(t, ctx, release.pool, tables)
	for _, table := range tables {
		if len(seeded.rows[table]) == 0 {
			t.Fatalf("v0.4.7-beta table %s has no seed rows; seed every table so the upgrade test reads it back", table)
		}
	}
	release.pool.Close()

	dumpFile := filepath.Join(t.TempDir(), "v0.4.7-beta.sql")
	dumpSchemaWithData(t, ctx, pgDump, dsn, schema, dumpFile)
	admin, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin store: %v", err)
	}
	defer admin.Close()
	if _, err := admin.pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
		t.Fatalf("drop v0.4.7-beta schema before restore: %v", err)
	}
	restoreDump(t, ctx, psql, dsn, dumpFile)

	upgraded := openSchemaStore(t, ctx, dsn, schema)
	restored := snapshotSchema(t, ctx, upgraded.pool, tables)
	compareSnapshots(t, "restored dump", seeded, restored, nil)

	if err := upgraded.Migrate(ctx); err != nil {
		t.Fatalf("Migrate the restored v0.4.7-beta database: %v", err)
	}
	checkUpgradedMigrationHistory(t, ctx, upgraded.pool)

	fresh, freshSchema := openEmptyIsolatedPostgres(t, ctx, dsn)
	if err := fresh.Migrate(ctx); err != nil {
		t.Fatalf("Migrate a fresh install: %v", err)
	}
	upgradedDump := normalizedSchemaDump(t, ctx, pgDump, dsn, schema)
	freshDump := normalizedSchemaDump(t, ctx, pgDump, dsn, freshSchema)
	if upgradedDump != freshDump {
		t.Fatalf("schema upgraded from v0.4.7-beta differs from a fresh install: %s",
			firstSchemaDifference(upgradedDump, freshDump))
	}

	migrated := snapshotSchema(t, ctx, upgraded.pool, tables)
	compareSnapshots(t, "migrated database", seeded, migrated, columnsAddedSinceV047Beta)
	checkV047BetaDataThroughStore(t, ctx, upgraded)
}

// applyV047BetaMigrations builds the v0.4.7-beta schema: it applies the
// embedded release migrations and records them with their checksums in one
// transaction, the same history table and records that release's Migrate wrote.
func applyV047BetaMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("list embedded migrations: %v", err)
	}
	var embedded []string
	for _, entry := range entries {
		if !entry.IsDir() {
			embedded = append(embedded, entry.Name())
		}
	}
	sort.Strings(embedded)
	if len(embedded) < len(v047BetaMigrations) {
		t.Fatalf("embedded migrations %v are fewer than the %d v0.4.7-beta shipped", embedded, len(v047BetaMigrations))
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin v0.4.7-beta migrations: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			checksum_sha256 TEXT,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create v0.4.7-beta migration history: %v", err)
	}
	for i, migration := range v047BetaMigrations {
		if embedded[i] != migration.name {
			t.Fatalf("embedded migration %d is %s, want v0.4.7-beta's %s", i+1, embedded[i], migration.name)
		}
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + migration.name)
		if err != nil {
			t.Fatalf("read migration %s: %v", migration.name, err)
		}
		if sum := fmt.Sprintf("%x", sha256.Sum256(sqlBytes)); sum != migration.checksum {
			t.Fatalf("migration %s changed since v0.4.7-beta (%s): checksum %s, want %s",
				migration.name, v047BetaCommit, sum, migration.checksum)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply v0.4.7-beta migration %s: %v", migration.name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, checksum_sha256) VALUES ($1, $2)`,
			migration.name, migration.checksum); err != nil {
			t.Fatalf("record v0.4.7-beta migration %s: %v", migration.name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit v0.4.7-beta migrations: %v", err)
	}
}

// seedV047BetaData fills every v0.4.7-beta table with synthetic rows: example
// domains, documentation address ranges and made-up names, never real data.
// The rows mix NULL and set optional columns, non-ASCII text, timestamps with
// microseconds and offsets, arrays and JSON.
func seedV047BetaData(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
BEGIN;

UPDATE app_settings
   SET retention_enabled = true,
       scan_retention_days = 90,
       retention_include_adhoc = true,
       updated_by = 'zoe.admin@example.com',
       updated_at = '2026-09-30 17:04:11.250731+00';

INSERT INTO users (id, subject, email, name, roles, created_at, last_login_at) VALUES
  ('10844a2e-333d-409e-b48e-86beac6b97b9', 'kc|4f1d8a90-77e2-4c55-9a0e-1c2b3d4e5f60', 'zoe.admin@example.com',
   'Zoë Ångström-Müller', '{admin,operator}', '2026-08-01 09:00:00+02', '2026-10-02 22:41:07.000123+02'),
  ('6eb97686-4b9a-4bfa-9c5a-910c68458048', 'kc|viewer-only-7731', NULL, NULL, '{}',
   '2026-08-15 12:30:00+00', '2026-08-15 12:30:00+00');

INSERT INTO sessions (id, subject, email, name, roles, created_at, expires_at) VALUES
  ('s3ss10n-synthetic-0001-aaaaaaaaaaaaaaaaaaaa', 'kc|4f1d8a90-77e2-4c55-9a0e-1c2b3d4e5f60', 'zoe.admin@example.com',
   'Zoë Ångström-Müller', '{admin,operator}', '2026-10-02 22:41:07.000123+02', '2026-10-03 06:41:07.000123+02'),
  ('s3ss10n-synthetic-0002-bbbbbbbbbbbbbbbbbbbb', 'kc|viewer-only-7731', NULL, NULL, '{}',
   '2026-10-01 08:00:00+00', '2026-10-01 16:00:00+00');

INSERT INTO auth_flows (state, nonce, pkce_verifier, return_to, created_at, expires_at) VALUES
  ('st-synthetic-6f2c', 'nonce-synthetic-91ab', 'pkce-synthetic-verifier-0123456789abcdefghijklmnopqrstuvwxyz',
   '/findings?severity=high&q=caf%C3%A9', '2026-10-02 22:40:00+02', '2026-10-02 22:50:00+02'),
  ('st-synthetic-7a3d', 'nonce-synthetic-02cd', 'pkce-synthetic-verifier-zyxwvutsrqponmlkjihgfedcba9876543210',
   NULL, '2026-10-02 23:00:00+02', '2026-10-02 23:10:00+02');

INSERT INTO service_accounts (id, name, role, token_hash, token_prefix, created_by, created_at, expires_at, last_used_at) VALUES
  ('963c7bcc-7f9a-4d9b-8085-89188d6b44af', 'ci-pipeline-exporter', 'viewer',
   '9d4f0c4b6a1e2f3d5c7b9a8e6f4d2c1b0a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c', 'nsc_Ab3d',
   'zoe.admin@example.com', '2026-09-01 10:00:00+00', '2027-03-01 00:00:00+00', '2026-10-02 03:15:00.5+00'),
  ('8dd22695-237b-4eed-9137-a2acec492ce9', 'Überwachung – nightly', 'operator',
   '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809', 'nsc_Zz09',
   NULL, '2026-09-05 10:00:00+00', NULL, NULL);

INSERT INTO scanner_nodes (id, name, endpoint, token, cidrs, tags, created_by, created_at, updated_at,
                           tls_server_ca, tls_client_cert, tls_client_key, templates_synced_at, max_concurrent_scans) VALUES
  ('dcfddfaf-b417-417d-8f7f-d67650349614', 'default', 'http://scanner:8081', 'synthetic-node-token-000000000000000001',
   '{}', '{}', NULL, '2026-08-01 09:00:00+00', '2026-08-01 09:00:00+00', '', '', '', NULL, 20),
  ('b27e6209-d9aa-423b-b3b5-86d688874b08', 'dmz-frankfurt-1', 'https://scanner-dmz.example.net:8443',
   'synthetic-node-token-000000000000000002', '{10.20.0.0/16,198.51.100.0/24}', '{eu-central,dmz,"Zone Süd"}',
   'zoe.admin@example.com', '2026-08-20 14:00:00+00', '2026-09-28 18:22:33.444555+00',
   'synthetic test CA placeholder', 'synthetic client certificate placeholder', 'synthetic client key placeholder',
   '2026-10-02 04:00:12.345678+00', 4);

INSERT INTO templates (id, source, path, yaml, content_sha256, name, author, severity, description, tags,
                       upstream_ref, revision, availability, created_by, created_at, updated_at) VALUES
  ('http-missing-security-headers', 'upstream', 'http/misconfiguration/http-missing-security-headers.yaml',
   E'id: http-missing-security-headers\ninfo:\n  name: HTTP Missing Security Headers\n  severity: info\n',
   'b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184', 'HTTP Missing Security Headers',
   'synthetic-author', 'info', 'Checks for missing security headers.', '{misconfig,headers,generic}',
   'v10.2.7', 3, 'active', NULL, '2026-08-01 09:05:00+00', '2026-09-30 04:00:00+00'),
  ('custom-login-panel-ümlaut', 'custom', 'custom/login-panel-ümlaut.yaml',
   E'id: custom-login-panel-ümlaut\ninfo:\n  name: Anmeldeseite – Prüfung\n  severity: medium\n',
   'c2a5e7f9b1d3c5e7f9a1b3d5c7e9f1a3b5d7c9e1f3a5b7d9c1e3f5a7b9d1c3e5', 'Anmeldeseite – Prüfung 🌙',
   '', 'medium', '', '{}', NULL, 1, 'active', 'zoe.admin@example.com',
   '2026-09-10 11:11:11.111111+00', '2026-09-10 11:11:11.111111+00'),
  ('cve-2099-0001-retired', 'upstream', 'http/cves/2099/CVE-2099-0001.yaml',
   E'id: cve-2099-0001-retired\ninfo:\n  name: Retired synthetic CVE\n  severity: high\n',
   'd3b07384d113edec49eaa6238ad5ff00d3b07384d113edec49eaa6238ad5ff00', 'Retired synthetic CVE',
   'synthetic-author', 'high', 'Removed upstream; kept for history.', '{cve,cve2099}',
   'v10.2.6', 2, 'unavailable', NULL, '2026-08-01 09:05:00+00', '2026-09-15 04:00:00+00');

INSERT INTO template_sets (id, name, created_by, created_at, updated_at, mode) VALUES
  ('a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58', 'Web baseline', 'zoe.admin@example.com',
   '2026-08-02 10:00:00+00', '2026-09-10 11:12:00+00', 'exact'),
  ('809150bd-2cd1-4e06-9171-bf16e0c95e1d', 'Alles außer Retired', NULL,
   '2026-08-03 10:00:00+00', '2026-08-03 10:00:00+00', 'exclude');

INSERT INTO template_set_members (template_set_id, template_id, added_by, added_at) VALUES
  ('a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58', 'http-missing-security-headers', 'zoe.admin@example.com', '2026-08-02 10:00:00+00'),
  ('a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58', 'custom-login-panel-ümlaut', NULL, '2026-09-10 11:12:00+00');

INSERT INTO template_set_exclusions (template_set_id, template_id, added_by, added_at) VALUES
  ('809150bd-2cd1-4e06-9171-bf16e0c95e1d', 'cve-2099-0001-retired', NULL, '2026-08-03 10:00:00+00');

INSERT INTO template_sync_runs (id, started_at, finished_at, status, ref_before, ref_after,
                                added, removed, updated, skipped, error, templates_commit, template_count) VALUES
  ('d5ee9992-d4ae-43d4-a17a-dfa4879fe43b', '2026-09-30 04:00:00+00', '2026-09-30 04:01:42.987654+00', 'success',
   'v10.2.6', 'v10.2.7', 12, 1, 37, 2, NULL, '5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5f6a7b8c9', 3),
  ('ea46deeb-f87e-41b6-8630-0516f95da1dd', '2026-10-01 04:00:00+00', NULL, 'running',
   'v10.2.7', NULL, 0, 0, 0, 0, NULL, NULL, NULL);

INSERT INTO targets (id, name, hosts, tags, created_by, created_at, updated_at) VALUES
  ('e5518069-8a40-480d-bb6b-d26895a3c142', 'Shop – Produktion', '{app.example.com,198.51.100.0/28}',
   '{prod,"Kunden-Portal",東京}', 'zoe.admin@example.com', '2026-08-04 08:00:00+00', '2026-09-01 08:00:00+00'),
  ('7fbfe5f3-ab71-414c-9117-84cc90897fae', 'legacy-api', '{https://203.0.113.7:8443/api}', '{}',
   NULL, '2026-08-05 08:00:00+00', '2026-08-05 08:00:00+00');

INSERT INTO scan_policies (id, name, template_set_id, rate_limit, concurrency, timeout_sec, max_host_error,
                           created_by, created_at, updated_at, discovery_enabled, discovery_ports,
                           discovery_timeout_sec, discovery_rate, discovery_probe_timeout_ms, discovery_retries,
                           discovery_scan_type, discovery_host_discovery, response_size_read, response_size_save,
                           notify_enabled, notify_recipients, notify_min_severity) VALUES
  ('ff78a637-51a2-4f4c-84d7-efd8ca16ece9', 'Nächtlich – Web', 'a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58',
   150, 25, 10, 30, 'zoe.admin@example.com', '2026-08-06 08:00:00+00', '2026-10-01 08:00:00.000001+00',
   true, '80,443,8000-8443', 600, 1000, 1500, 2, 'connect', false, 4194304, 524288,
   true, '{secops@example.com,"Jürgen Weiß <jurgen@example.org>"}', 'medium'),
  ('ff25dfda-cd65-4239-9807-49803cca89bb', 'ad-hoc defaults', '809150bd-2cd1-4e06-9171-bf16e0c95e1d',
   NULL, NULL, NULL, NULL, NULL, '2026-08-07 08:00:00+00', '2026-08-07 08:00:00+00',
   false, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

INSERT INTO schedules (id, name, cron, enabled, next_run_at, last_run_at, last_scan_id, created_by,
                       created_at, updated_at, scan_policy_id, target_id, timezone) VALUES
  ('38affc28-4c01-4b31-a0b4-201867f8a20e', 'Werktags 03:00', '0 3 * * 1-5', true,
   '2026-10-05 01:00:00+00', '2026-10-02 01:00:00.004321+00', NULL, 'zoe.admin@example.com',
   '2026-08-08 08:00:00+00', '2026-09-20 08:00:00+00',
   'ff78a637-51a2-4f4c-84d7-efd8ca16ece9', 'e5518069-8a40-480d-bb6b-d26895a3c142', 'Europe/Berlin'),
  ('d1887995-ae89-4dc6-a5bc-fde7807a2594', 'paused legacy sweep', '30 2 1 * *', false,
   NULL, NULL, NULL, NULL, '2026-08-09 08:00:00+00', '2026-08-09 08:00:00+00',
   'ff25dfda-cd65-4239-9807-49803cca89bb', '7fbfe5f3-ab71-414c-9117-84cc90897fae', 'UTC');

INSERT INTO scans (id, node_scan_id, state, spec, nuclei_version, templates_commit, error, created_at,
                   started_at, finished_at, target_id, template_set_id, source, schedule_id, raw_object_key,
                   log_object_key, node_id, scan_policy_id, discovered_targets, covered_endpoints,
                   coverage_warning, skipped_finding_count, coverage_origin,
                   notify_enabled, notify_recipients, notify_min_severity) VALUES
  ('cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'node-run-0001', 'complete',
   '{"hosts": ["app.example.com", "198.51.100.0/28"], "rate_limit": 150, "templates": ["http-missing-security-headers", "custom-login-panel-ümlaut"], "discovery": {"ports": "80,443,8000-8443", "enabled": true}}',
   'v3.4.10', '5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5f6a7b8c9', NULL,
   '2026-10-02 01:00:00.004321+00', '2026-10-02 01:00:02+00', '2026-10-02 01:17:45.678901+00',
   'e5518069-8a40-480d-bb6b-d26895a3c142', 'a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58', 'schedule',
   '38affc28-4c01-4b31-a0b4-201867f8a20e', 'scans/cfc3a63a-5eb6-4004-ada1-3d124a6c1781/raw.jsonl',
   'scans/cfc3a63a-5eb6-4004-ada1-3d124a6c1781/log.txt', 'b27e6209-d9aa-423b-b3b5-86d688874b08',
   'ff78a637-51a2-4f4c-84d7-efd8ca16ece9', '{app.example.com:443,198.51.100.5:8443}',
   '[{"endpoint": "app.example.com:443", "template_id": "http-missing-security-headers"}, {"endpoint": "198.51.100.5:8443", "template_id": "custom-login-panel-ümlaut"}]',
   NULL, 1, 'node', true, '{secops@example.com,"Jürgen Weiß <jurgen@example.org>"}', 'medium'),
  ('47df5ac5-9906-4999-b147-fd30f25a51f6', NULL, 'failed',
   '{"hosts": ["https://203.0.113.7:8443/api"], "templates": []}',
   NULL, NULL, 'Scanner nicht erreichbar: connection refused (Ü-Test)',
   '2026-10-01 12:00:00+00', NULL, '2026-10-01 12:00:30+00',
   '7fbfe5f3-ab71-414c-9117-84cc90897fae', '809150bd-2cd1-4e06-9171-bf16e0c95e1d', 'adhoc',
   NULL, NULL, NULL, NULL, 'ff25dfda-cd65-4239-9807-49803cca89bb', NULL, NULL,
   NULL, 0, 'import_untrusted', false, NULL, NULL),
  ('8cf6a182-5e43-4d8e-b60a-494f19e7d9e1', NULL, 'complete',
   '{"hosts": ["https://203.0.113.7:8443/api"], "imported": true, "bundle": {"format": "goodnightsec/nsc/scan-bundle", "version": 1}}',
   'v3.4.9', NULL, NULL,
   '2026-09-20 09:00:00+00', '2026-09-20 09:00:00+00', '2026-09-20 09:00:00+00',
   '7fbfe5f3-ab71-414c-9117-84cc90897fae', NULL, 'import',
   NULL, NULL, NULL, 'dcfddfaf-b417-417d-8f7f-d67650349614', NULL, '{}', '[]',
   'Trace incomplete for 2 requests', 0, 'import_trusted', false, '{}', NULL);

UPDATE schedules SET last_scan_id = 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781'
 WHERE id = '38affc28-4c01-4b31-a0b4-201867f8a20e';

INSERT INTO finding_lifecycle (id, dedup_key, template_id, name, severity, host, matched_at, type, cve, tags,
                               first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, latest_occurrence_id,
                               disposition_note, disposition_by, disposition_at, disposition, accept_expires_at,
                               recast_severity, times_mitigated, recast_note, recast_by, recast_at,
                               last_covering_scan, result_discriminator, endpoint_key,
                               matcher_name, extractor_name, extracted_results) VALUES
  (1, 'dk-synthetic-0001', 'http-missing-security-headers', 'HTTP Missing Security Headers', 'info',
   'app.example.com', 'https://app.example.com/', 'http', '{}', '{misconfig,headers,generic}',
   'cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781',
   '2026-10-02 01:05:00+00', '2026-10-02 01:05:00+00', NULL,
   'Akzeptiert bis zum Relaunch – siehe Ticket „WEB-42“', 'zoe.admin@example.com', '2026-10-02 09:30:00+02',
   'accepted', '2026-12-31 23:59:59.999999+01', 'low', 2, 'Nur intern erreichbar', 'zoe.admin@example.com',
   '2026-10-02 09:31:00+02', 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'app.example.com:443',
   'strict-transport-security', '', '{}'),
  (2, 'dk-synthetic-0002', 'custom-login-panel-ümlaut', NULL, NULL, NULL, NULL, NULL,
   '{CVE-2099-0002}', '{}', NULL, NULL,
   '2026-09-20 09:00:00+00', '2026-09-20 09:00:00+00', NULL,
   NULL, NULL, NULL, 'none', NULL, NULL, 0, NULL, NULL, NULL, NULL, '', '', '', 'version', '{"2.4.1","β-release"}');

INSERT INTO findings (id, scan_id, template_id, name, severity, host, matched_at, type, raw, created_at,
                      cve, tags, target_id, dedup_key, finding_id, raw_line, result_discriminator,
                      matcher_name, extractor_name, extracted_results) VALUES
  (1, 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'http-missing-security-headers', 'HTTP Missing Security Headers',
   'info', 'app.example.com', 'https://app.example.com/', 'http',
   '{"host": "app.example.com", "info": {"name": "HTTP Missing Security Headers", "tags": ["misconfig", "headers"], "severity": "info"}, "type": "http", "matched-at": "https://app.example.com/", "template-id": "http-missing-security-headers", "matcher-name": "x-frame-options"}',
   '2026-10-02 01:05:00+00', '{}', '{misconfig,headers}', 'e5518069-8a40-480d-bb6b-d26895a3c142',
   'dk-synthetic-0001', 1,
   '{"template-id":"http-missing-security-headers","host":"app.example.com","matcher-name":"x-frame-options"}',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'x-frame-options', '', '{}'),
  (2, 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'http-missing-security-headers', 'HTTP Missing Security Headers',
   'info', 'app.example.com', 'https://app.example.com/', 'http',
   '{"host": "app.example.com", "info": {"name": "HTTP Missing Security Headers", "severity": "info"}, "type": "http", "matched-at": "https://app.example.com/", "template-id": "http-missing-security-headers", "matcher-name": "strict-transport-security", "meta": {"note": "Prüfung 🌙", "empty": null, "ratio": 0.25}}',
   '2026-10-02 01:05:00.000001+00', '{}', '{misconfig,headers,generic}', 'e5518069-8a40-480d-bb6b-d26895a3c142',
   'dk-synthetic-0001', 1, NULL,
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'strict-transport-security', '', '{}'),
  (3, '8cf6a182-5e43-4d8e-b60a-494f19e7d9e1', 'custom-login-panel-ümlaut', NULL, NULL, NULL, NULL, NULL,
   '{"template-id": "custom-login-panel-ümlaut", "extractor-name": "version", "extracted-results": ["2.4.1", "β-release"]}',
   '2026-09-20 09:00:00+00', '{CVE-2099-0002}', '{}', '7fbfe5f3-ab71-414c-9117-84cc90897fae',
   'dk-synthetic-0002', 2, NULL, '', '', 'version', '{"2.4.1","β-release"}');

UPDATE finding_lifecycle SET latest_occurrence_id = 2 WHERE id = 1;
UPDATE finding_lifecycle SET latest_occurrence_id = 3 WHERE id = 2;
SELECT setval('findings_id_seq', 3);
SELECT setval('finding_lifecycle_id_seq', 2);

INSERT INTO scan_notification_outbox (scan_id, kind, payload, created_at, claimed_at) VALUES
  ('cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'digest',
   '{"new": 2, "fixed": 0, "counts": {"info": 2, "medium": 0}, "target": "Shop – Produktion", "recipients": ["secops@example.com"]}',
   '2026-10-02 01:17:45.678901+00', '2026-10-02 01:17:46.000002+00'),
  ('47df5ac5-9906-4999-b147-fd30f25a51f6', 'failed',
   '{"reason": "Scanner nicht erreichbar", "detail": null}',
   '2026-10-01 12:00:30+00', NULL);

COMMIT;
`); err != nil {
		t.Fatalf("seed v0.4.7-beta data: %v", err)
	}
}

// schemaSnapshot holds every row of a schema's tables as to_jsonb column
// values keyed by primary key, plus the state of its sequences.
type schemaSnapshot struct {
	rows      map[string]map[string]map[string]json.RawMessage
	sequences map[string]string
}

func schemaTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT tablename FROM pg_tables
		 WHERE schemaname = current_schema() AND tablename <> 'schema_migrations'
		 ORDER BY tablename`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	return tables
}

func snapshotSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tables []string) schemaSnapshot {
	t.Helper()
	snap := schemaSnapshot{
		rows:      make(map[string]map[string]map[string]json.RawMessage, len(tables)),
		sequences: make(map[string]string),
	}
	for _, table := range tables {
		pkRows, err := pool.Query(ctx, `
			SELECT a.attname
			  FROM pg_index i
			  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
			 WHERE i.indrelid = $1::regclass AND i.indisprimary
			 ORDER BY array_position(i.indkey::int2[], a.attnum)`, table)
		if err != nil {
			t.Fatalf("read primary key of %s: %v", table, err)
		}
		pk, err := pgx.CollectRows(pkRows, pgx.RowTo[string])
		if err != nil || len(pk) == 0 {
			t.Fatalf("read primary key of %s: %v (columns %v)", table, err, pk)
		}

		rows, err := pool.Query(ctx, "SELECT to_jsonb(t)::text FROM "+pgx.Identifier{table}.Sanitize()+" AS t")
		if err != nil {
			t.Fatalf("read rows of %s: %v", table, err)
		}
		texts, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("read rows of %s: %v", table, err)
		}
		byKey := make(map[string]map[string]json.RawMessage, len(texts))
		for _, text := range texts {
			var row map[string]json.RawMessage
			if err := json.Unmarshal([]byte(text), &row); err != nil {
				t.Fatalf("decode row of %s: %v", table, err)
			}
			keyParts := make([]string, 0, len(pk))
			for _, column := range pk {
				keyParts = append(keyParts, string(row[column]))
			}
			byKey[strings.Join(keyParts, ",")] = row
		}
		snap.rows[table] = byKey
	}

	seqRows, err := pool.Query(ctx, `
		SELECT sequencename FROM pg_sequences
		 WHERE schemaname = current_schema() ORDER BY sequencename`)
	if err != nil {
		t.Fatalf("list sequences: %v", err)
	}
	sequences, err := pgx.CollectRows(seqRows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("list sequences: %v", err)
	}
	for _, sequence := range sequences {
		var state string
		if err := pool.QueryRow(ctx,
			"SELECT last_value || ' ' || is_called FROM "+pgx.Identifier{sequence}.Sanitize()).Scan(&state); err != nil {
			t.Fatalf("read sequence %s: %v", sequence, err)
		}
		snap.sequences[sequence] = state
	}
	return snap
}

// compareSnapshots checks that got holds exactly the rows of want, each with
// unchanged values. Columns absent from want must be listed in added with the
// value every row holds.
func compareSnapshots(t *testing.T, label string, want, got schemaSnapshot, added map[string]map[string]string) {
	t.Helper()
	for table, wantRows := range want.rows {
		gotRows := got.rows[table]
		if len(gotRows) != len(wantRows) {
			t.Errorf("%s: table %s has %d rows, want the %d seeded", label, table, len(gotRows), len(wantRows))
		}
		addedHere := make(map[string]bool)
		for key, wantRow := range wantRows {
			gotRow, ok := gotRows[key]
			if !ok {
				t.Errorf("%s: %s row %s is missing", label, table, key)
				continue
			}
			for column, wantValue := range wantRow {
				gotValue, ok := gotRow[column]
				if !ok {
					t.Errorf("%s: %s row %s lost column %s", label, table, key, column)
					continue
				}
				if !bytes.Equal(gotValue, wantValue) {
					t.Errorf("%s: %s row %s column %s = %s, want %s", label, table, key, column, gotValue, wantValue)
				}
			}
			for column, gotValue := range gotRow {
				if _, ok := wantRow[column]; ok {
					continue
				}
				expected, ok := added[table][column]
				if !ok {
					t.Errorf("%s: %s.%s was added after v0.4.7-beta; list the value upgraded rows hold in columnsAddedSinceV047Beta (row %s holds %s)",
						label, table, column, key, gotValue)
					continue
				}
				addedHere[column] = true
				if !jsonEqual(gotValue, json.RawMessage(expected)) {
					t.Errorf("%s: upgraded %s row %s column %s = %s, want %s", label, table, key, column, gotValue, expected)
				}
			}
		}
		for column := range added[table] {
			if !addedHere[column] {
				t.Errorf("%s: columnsAddedSinceV047Beta lists %s.%s, but the migrated rows have no such new column", label, table, column)
			}
		}
	}
	for table := range added {
		if _, ok := want.rows[table]; !ok {
			t.Errorf("%s: columnsAddedSinceV047Beta lists table %s, which v0.4.7-beta has no seed rows for", label, table)
		}
	}
	for sequence, wantState := range want.sequences {
		if gotState := got.sequences[sequence]; gotState != wantState {
			t.Errorf("%s: sequence %s = %q, want %q", label, sequence, gotState, wantState)
		}
	}
}

func jsonEqual(a, b json.RawMessage) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}

// checkUpgradedMigrationHistory checks that the v0.4.7-beta records survive
// unchanged and that Migrate recorded every later migration once.
func checkUpgradedMigrationHistory(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT version, checksum_sha256 FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read migration history: %v", err)
	}
	type record struct {
		Version  string
		Checksum string
	}
	history, err := pgx.CollectRows(rows, pgx.RowToStructByPos[record])
	if err != nil {
		t.Fatalf("read migration history: %v", err)
	}
	if want := currentMigrationCount(t); len(history) != want {
		t.Fatalf("upgraded migration history has %d records, want %d: %v", len(history), want, history)
	}
	for i, migration := range v047BetaMigrations {
		if history[i].Version != migration.name || history[i].Checksum != migration.checksum {
			t.Fatalf("upgraded migration record %d = %v, want v0.4.7-beta's %s %s", i+1, history[i], migration.name, migration.checksum)
		}
	}
}

// checkV047BetaDataThroughStore reads seeded rows through the store API, the
// way the upgraded release reads them.
func checkV047BetaDataThroughStore(t *testing.T, ctx context.Context, st *Store) {
	t.Helper()
	settings, err := st.GetAppSettings(ctx)
	if err != nil {
		t.Fatalf("read upgraded app settings: %v", err)
	}
	if !settings.RetentionEnabled || settings.ScanRetentionDays == nil || *settings.ScanRetentionDays != 90 ||
		!settings.RetentionIncludeAdhoc || settings.UpdatedBy != "zoe.admin@example.com" {
		t.Errorf("upgraded app settings = %#v, want the seeded 90-day retention", settings)
	}

	scan, err := st.GetScan(ctx, "cfc3a63a-5eb6-4004-ada1-3d124a6c1781")
	if err != nil {
		t.Fatalf("read upgraded scan: %v", err)
	}
	if scan.State != "complete" || scan.TargetName != "Shop – Produktion" || scan.NodeName != "dmz-frankfurt-1" ||
		!scan.NotifyEnabled || scan.NotifyMinSeverity != "medium" ||
		strings.Join(scan.NotifyRecipients, "|") != "secops@example.com|Jürgen Weiß <jurgen@example.org>" ||
		len(scan.CoveredEndpoints) != 2 || scan.CoveredEndpoints[1].TemplateID != "custom-login-panel-ümlaut" ||
		!scan.HasRaw || !scan.HasLog || scan.SkippedFindingCount != 1 {
		t.Errorf("upgraded scan = %#v, want the seeded scheduled scan", scan)
	}
	failed, err := st.GetScan(ctx, "47df5ac5-9906-4999-b147-fd30f25a51f6")
	if err != nil {
		t.Fatalf("read upgraded failed scan: %v", err)
	}
	if failed.State != "failed" || failed.Error != "Scanner nicht erreichbar: connection refused (Ü-Test)" ||
		failed.NodeID != "" || failed.CoveredEndpoints != nil || failed.DiscoveredTargets != nil || failed.NotifyRecipients != nil {
		t.Errorf("upgraded failed scan = %#v, want the seeded NULLs kept", failed)
	}

	schedule, err := st.GetSchedule(ctx, "38affc28-4c01-4b31-a0b4-201867f8a20e")
	if err != nil {
		t.Fatalf("read upgraded schedule: %v", err)
	}
	wantNext := time.Date(2026, 10, 5, 1, 0, 0, 0, time.UTC)
	if schedule.Cron != "0 3 * * 1-5" || schedule.Timezone != "Europe/Berlin" || !schedule.Enabled ||
		schedule.NextRunAt == nil || !schedule.NextRunAt.Equal(wantNext) ||
		schedule.LastScanID != "cfc3a63a-5eb6-4004-ada1-3d124a6c1781" {
		t.Errorf("upgraded schedule = %#v, want the seeded Europe/Berlin schedule", schedule)
	}

	target, err := st.GetTarget(ctx, "e5518069-8a40-480d-bb6b-d26895a3c142")
	if err != nil {
		t.Fatalf("read upgraded target: %v", err)
	}
	if target.Name != "Shop – Produktion" || strings.Join(target.Hosts, "|") != "app.example.com|198.51.100.0/28" ||
		strings.Join(target.Tags, "|") != "prod|Kunden-Portal|東京" {
		t.Errorf("upgraded target = %#v, want the seeded target", target)
	}
}

// findPSQL finds the psql that restores the dump: NSC_TEST_PSQL, the psql next
// to pg_dump, or psql on PATH.
func findPSQL(t *testing.T, pgDump string) string {
	t.Helper()
	if configured := os.Getenv("NSC_TEST_PSQL"); configured != "" {
		return configured
	}
	if sibling := filepath.Join(filepath.Dir(pgDump), "psql"); sibling != pgDump {
		if info, err := os.Stat(sibling); err == nil && !info.IsDir() {
			return sibling
		}
	}
	if path, err := exec.LookPath("psql"); err == nil {
		return path
	}
	t.Fatal("NSC_TEST_DATABASE_URL is set but psql was not found; install the PostgreSQL client or set NSC_TEST_PSQL")
	return ""
}

func dumpSchemaWithData(t *testing.T, ctx context.Context, pgDump, dsn, schema, file string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, pgDump,
		"--no-owner",
		"--no-privileges",
		"--schema="+schema,
		"--file="+file,
		"--dbname="+dsn,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pg_dump v0.4.7-beta schema %s: %v\n%s", schema, err, output)
	}

	// pg_dump 17 and newer always emit SET transaction_timeout, which a
	// PostgreSQL 16 server rejects. The setting only guards the restore
	// session, so drop it rather than relax ON_ERROR_STOP.
	dump, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read v0.4.7-beta dump: %v", err)
	}
	lines := strings.Split(string(dump), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !strings.HasPrefix(line, "SET transaction_timeout ") {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(file, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatalf("write v0.4.7-beta dump: %v", err)
	}
}

func restoreDump(t *testing.T, ctx context.Context, psql, dsn, file string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, psql,
		"--no-psqlrc",
		"--quiet",
		"--single-transaction",
		"--set=ON_ERROR_STOP=1",
		"--file="+file,
		"--dbname="+dsn,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restore v0.4.7-beta dump: %v\n%s", err, output)
	}
}

// openSchemaStore opens a new pool on an existing schema, so no connection
// carries prepared statements from before the restore.
func openSchemaStore(t *testing.T, ctx context.Context, dsn, schema string) *Store {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open restored schema pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return &Store{pool: pool}
}
