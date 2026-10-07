-- Follow-ups to the admin-switchable upstream template source (#343, review of PR #344):
-- the sync history must show which configured source each run read and when the
-- source itself was last changed, and template restorations must not be counted
-- as content changes.

ALTER TABLE template_sync_runs
    ADD COLUMN restored integer,
    ADD COLUMN source_repo text,
    ADD COLUMN source_ref text;

ALTER TABLE app_settings
    ADD COLUMN template_sync_source_updated_at timestamptz,
    ADD COLUMN template_sync_source_updated_by text;

COMMENT ON COLUMN template_sync_runs.restored IS 'Templates restored from unavailable back to active by this run; NULL for pre-migration history, where a restore was counted as updated.';
COMMENT ON COLUMN template_sync_runs.source_repo IS 'Sanitized (credential-free) upstream repository this run actually read; NULL for pre-migration runs.';
COMMENT ON COLUMN template_sync_runs.source_ref IS 'Configured ref (latest / branch / tag / SHA) this run actually read; NULL for pre-migration runs.';
COMMENT ON COLUMN app_settings.template_sync_source_updated_at IS 'When the template sync source was last changed by an administrator; NULL while it has only ever been seeded from the environment.';
COMMENT ON COLUMN app_settings.template_sync_source_updated_by IS 'Subject of the administrator who last changed the template sync source; NULL while only seeded.';