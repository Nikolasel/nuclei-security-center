-- Phase 2: finding lifecycle.
--
-- Until now `findings` was a flat per-scan insert: every scan re-inserted the same
-- vulnerability as a brand-new row with no cross-scan identity, so nothing could
-- carry a lifecycle (first/last seen, triage status). Triage state that lived on a
-- per-scan row would reset every run.
--
-- We keep `findings` as the immutable per-scan OCCURRENCE log (it still holds the
-- verbatim raw JSON and answers "what did scan X observe"), and add a deduplicated
-- entity `finding_lifecycle` keyed on (target_id, template_id, matched_at) — the key
-- from ARCHITECTURE.md §3. That entity is what users triage; its status survives
-- across scans. "Resolved/gone" is derived at read time (last-seen != the target's
-- latest scan), so it is never a stale persisted flag.

-- 1. Occurrences gain their scope (target) + a stable dedup key + a link to the
--    lifecycle entity they belong to. dedup_key uses the unit-separator (0x1f) as a
--    delimiter that cannot appear in the component values; the ingest path computes
--    the identical key in Go (see store.DedupKey).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS target_id  UUID;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedup_key  TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_id BIGINT;

-- Backfill the scope from the scan the occurrence came from (ad-hoc scans: NULL).
UPDATE findings f SET target_id = s.target_id
  FROM scans s WHERE s.id = f.scan_id AND f.target_id IS NULL;

-- Backfill the dedup key. coalesce so ad-hoc (no target) / empty matched_at are stable.
UPDATE findings SET dedup_key =
    coalesce(target_id::text, '-') || E'\x1f' || template_id || E'\x1f' || coalesce(matched_at, '')
  WHERE dedup_key IS NULL;

ALTER TABLE findings ALTER COLUMN dedup_key SET NOT NULL;
CREATE INDEX IF NOT EXISTS findings_dedup_idx      ON findings (dedup_key);
CREATE INDEX IF NOT EXISTS findings_target_idx     ON findings (target_id);
CREATE INDEX IF NOT EXISTS findings_finding_id_idx ON findings (finding_id);

-- 2. The deduplicated, triageable entity. One row per distinct (target, template,
--    matched_at); columns denormalise the LATEST occurrence's display fields plus
--    the first/last-seen scan bookkeeping and the triage status.
CREATE TABLE IF NOT EXISTS finding_lifecycle (
    id                   BIGSERIAL PRIMARY KEY,
    dedup_key            TEXT NOT NULL UNIQUE,
    target_id            UUID REFERENCES targets(id) ON DELETE SET NULL,
    template_id          TEXT NOT NULL,
    name                 TEXT,
    severity             TEXT,
    host                 TEXT,
    matched_at           TEXT,
    type                 TEXT,
    cve                  TEXT[] NOT NULL DEFAULT '{}',
    tags                 TEXT[] NOT NULL DEFAULT '{}',
    first_seen_scan      UUID REFERENCES scans(id) ON DELETE SET NULL,
    last_seen_scan       UUID REFERENCES scans(id) ON DELETE SET NULL,
    first_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    latest_occurrence_id BIGINT REFERENCES findings(id) ON DELETE SET NULL,
    -- Manual triage state; distinct from the derived "gone/resolved" facet.
    status     TEXT NOT NULL DEFAULT 'open'
               CHECK (status IN ('open', 'triaged', 'false_positive', 'fixed')),
    status_note TEXT,
    status_by   TEXT,
    status_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS finding_lifecycle_status_idx    ON finding_lifecycle (status);
CREATE INDEX IF NOT EXISTS finding_lifecycle_target_idx    ON finding_lifecycle (target_id);
CREATE INDEX IF NOT EXISTS finding_lifecycle_severity_idx  ON finding_lifecycle (severity);
CREATE INDEX IF NOT EXISTS finding_lifecycle_last_seen_idx ON finding_lifecycle (last_seen_scan);
CREATE INDEX IF NOT EXISTS finding_lifecycle_first_seen_idx ON finding_lifecycle (first_seen_scan);
CREATE INDEX IF NOT EXISTS finding_lifecycle_cve_idx  ON finding_lifecycle USING GIN (cve);
CREATE INDEX IF NOT EXISTS finding_lifecycle_tags_idx ON finding_lifecycle USING GIN (tags);

-- 3. Backfill lifecycle rows from the existing occurrence history: the newest
--    occurrence per dedup_key supplies the display fields + last-seen; window
--    functions supply first-seen. All backfilled rows start 'open'.
INSERT INTO finding_lifecycle (
    dedup_key, target_id, template_id, name, severity, host, matched_at, type, cve, tags,
    first_seen_scan, first_seen_at, last_seen_scan, last_seen_at, latest_occurrence_id, status)
SELECT dedup_key, target_id, template_id, name, severity, host, matched_at, type, cve, tags,
       first_scan, first_at, scan_id, created_at, id, 'open'
FROM (
    SELECT f.*,
        row_number() OVER (PARTITION BY dedup_key ORDER BY created_at DESC, id DESC) AS rn_latest,
        first_value(scan_id)  OVER (PARTITION BY dedup_key ORDER BY created_at ASC, id ASC) AS first_scan,
        min(created_at)       OVER (PARTITION BY dedup_key) AS first_at
    FROM findings f
) ranked
WHERE rn_latest = 1
ON CONFLICT (dedup_key) DO NOTHING;

-- 4. Point each occurrence at its lifecycle entity, then enforce the FK.
UPDATE findings f SET finding_id = l.id
  FROM finding_lifecycle l WHERE l.dedup_key = f.dedup_key AND f.finding_id IS NULL;

ALTER TABLE findings
  ADD CONSTRAINT findings_finding_id_fkey
  FOREIGN KEY (finding_id) REFERENCES finding_lifecycle(id) ON DELETE SET NULL;
