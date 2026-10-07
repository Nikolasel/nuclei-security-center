-- Admin-switchable upstream template source (#343). The singleton app_settings
-- row gains the syncer's repo/ref; TEMPLATE_SYNC_REPO / TEMPLATE_SYNC_REF seed
-- them exactly once at startup (NULL = never seeded), after which PostgreSQL is
-- the system of record and env changes only log a drift note. An explicitly
-- empty template_sync_repo keeps meaning "upstream sync disabled" while custom
-- templates and bundle distribution keep working. TEMPLATE_SYNC_INTERVAL and
-- TEMPLATE_SYNC_DIR stay env-only.

ALTER TABLE app_settings
    ADD COLUMN template_sync_repo text,
    ADD COLUMN template_sync_ref text;

COMMENT ON COLUMN app_settings.template_sync_repo IS 'Seeded once from TEMPLATE_SYNC_REPO (empty = upstream sync disabled); DB wins afterward. Raw value may embed credentials — never returned by the API (only the sanitized URL is).';
COMMENT ON COLUMN app_settings.template_sync_ref IS 'Seeded once from TEMPLATE_SYNC_REF; latest = highest stable semver tag, else a git ref name or commit SHA resolved at sync/preview time';