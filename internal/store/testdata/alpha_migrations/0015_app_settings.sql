-- Global app settings (#95). The first cross-cutting "app setting" (as opposed
-- to a per-resource row like targets/schedules): a single-row table an admin
-- edits at runtime, no redeploy — matching how schedules are DB-driven rather
-- than cron-in-config.
--
-- Holds the scan-retention policy: retention_enabled + scan_retention_days. The
-- background RetentionSweeper deletes scans older than the window, reusing the
-- existing per-scan delete primitive (store.DeleteScan). Disabled unless
-- retention_enabled is true AND scan_retention_days is a positive integer,
-- mirroring the "unset ⇒ disabled" convention used for S3_ENDPOINT/OIDC_ISSUER.
--
-- retention_include_adhoc controls whether ad-hoc scans (no target_id) are swept
-- too. Off by default (target-linked scans only). When on, ad-hoc scans are
-- deleted purely on age — safe because store.DeleteScan's lifecycle repair
-- deletes any now-evidence-free finding_lifecycle rows rather than leaving them
-- stale (their detection state is always derived as "active" anyway, since the
-- latest-scan comparison is gated on a non-null target).
CREATE TABLE IF NOT EXISTS app_settings (
    id                      BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),  -- single row
    retention_enabled       BOOLEAN NOT NULL DEFAULT false,
    scan_retention_days     INTEGER,                                      -- NULL = unset
    retention_include_adhoc BOOLEAN NOT NULL DEFAULT false,
    updated_by              TEXT,                                         -- OIDC subject / service account
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the singleton row so reads never have to special-case "no row yet".
INSERT INTO app_settings (id) VALUES (true) ON CONFLICT (id) DO NOTHING;
