-- Admin-switchable upstream template source (#343). The singleton app_settings
-- row gains the syncer's repo/ref; TEMPLATE_SYNC_REPO / TEMPLATE_SYNC_REF seed
-- them exactly once at startup (NULL = never seeded), after which PostgreSQL is
-- the system of record and env changes only log a drift note. An explicitly
-- empty template_sync_repo keeps meaning "upstream sync disabled" while custom
-- templates and bundle distribution keep working. TEMPLATE_SYNC_INTERVAL and
-- TEMPLATE_SYNC_DIR stay env-only. The sync history records which configured
-- source each run actually read and when the source itself was last changed,
-- and template restorations are not counted as content changes.

ALTER TABLE app_settings
    ADD COLUMN template_sync_repo text,
    ADD COLUMN template_sync_ref text,
    ADD COLUMN template_sync_source_updated_at timestamptz,
    ADD COLUMN template_sync_source_updated_by text;

ALTER TABLE template_sync_runs
    ADD COLUMN restored integer,
    ADD COLUMN source_repo text,
    ADD COLUMN source_ref text;

COMMENT ON COLUMN app_settings.template_sync_repo IS 'Seeded once from TEMPLATE_SYNC_REPO (empty = upstream sync disabled); DB wins afterward. Raw value may embed credentials — never returned by the API (only the sanitized URL is).';
COMMENT ON COLUMN app_settings.template_sync_ref IS 'Seeded once from TEMPLATE_SYNC_REF; latest = highest stable semver tag, else a git ref name or commit SHA resolved at sync/preview time';
COMMENT ON COLUMN app_settings.template_sync_source_updated_at IS 'When the template sync source was last changed by an administrator; NULL while it has only ever been seeded from the environment.';
COMMENT ON COLUMN app_settings.template_sync_source_updated_by IS 'Subject of the administrator who last changed the template sync source; NULL while only seeded.';
COMMENT ON COLUMN template_sync_runs.restored IS 'Templates restored from unavailable back to active by this run; NULL for pre-migration history, where a restore was counted as updated.';
COMMENT ON COLUMN template_sync_runs.source_repo IS 'Sanitized (credential-free) upstream repository this run actually read; NULL for pre-migration runs.';
COMMENT ON COLUMN template_sync_runs.source_ref IS 'Configured ref (latest / branch / tag / SHA) this run actually read; NULL for pre-migration runs.';