-- Phase 2: Tenable.sc-style finding lifecycle.
--
-- The lifecycle now separates two dimensions, like Tenable Security Center:
--
--   * DETECTION STATE — automatic, derived at read time from scan observation:
--     New / Active / Resurfaced (cumulative) and Mitigated / Previously Mitigated
--     (no longer detected). Closure is evidence-driven — there is no manual "fixed".
--
--   * DISPOSITION — the only thing analysts set manually: Accept Risk (with an
--     optional expiry) and False Positive, plus Recast Risk (a severity override).
--
-- This replaces the free-form triage `status` from migration 0005. Light workflow
-- dispositions (investigating / in progress) are intentionally deferred — see
-- ARCHITECTURE.md §8 "Beyond MVP".

-- Disposition (analyst overlay). 'none' = let the detection state speak.
ALTER TABLE finding_lifecycle ADD COLUMN IF NOT EXISTS disposition TEXT NOT NULL DEFAULT 'none';

-- Map the old status vocabulary. 'fixed'/'open'/'triaged' are no longer manual
-- states — Mitigated (scan evidence) is the "fixed" signal now.
UPDATE finding_lifecycle SET disposition =
    CASE status
        WHEN 'false_positive' THEN 'false_positive'
        WHEN 'risk_accepted'  THEN 'accepted'
        ELSE 'none'
    END;

ALTER TABLE finding_lifecycle
    ADD CONSTRAINT finding_lifecycle_disposition_chk
    CHECK (disposition IN ('none', 'false_positive', 'accepted'));

-- Accept Risk expiry: an accepted finding whose expiry has passed falls back to its
-- detection state, resurfacing for re-review instead of hiding forever.
ALTER TABLE finding_lifecycle ADD COLUMN IF NOT EXISTS accept_expires_at TIMESTAMPTZ;

-- Recast Risk: an analyst severity override. NULL = use the scan-observed severity.
ALTER TABLE finding_lifecycle ADD COLUMN IF NOT EXISTS recast_severity TEXT;
ALTER TABLE finding_lifecycle
    ADD CONSTRAINT finding_lifecycle_recast_chk
    CHECK (recast_severity IS NULL OR recast_severity IN ('critical', 'high', 'medium', 'low', 'info'));

-- Mitigation history: how many times this finding has come back after being gone.
-- Drives Resurfaced (active again after mitigation) and Previously Mitigated
-- (mitigated, returned, gone again). Maintained at ingest; existing rows start at 0.
ALTER TABLE finding_lifecycle ADD COLUMN IF NOT EXISTS times_mitigated INT NOT NULL DEFAULT 0;

-- Rename the status audit trio to disposition_*, and add a parallel recast trio.
ALTER TABLE finding_lifecycle RENAME COLUMN status_note TO disposition_note;
ALTER TABLE finding_lifecycle RENAME COLUMN status_by   TO disposition_by;
ALTER TABLE finding_lifecycle RENAME COLUMN status_at   TO disposition_at;
ALTER TABLE finding_lifecycle ADD COLUMN IF NOT EXISTS recast_note TEXT;
ALTER TABLE finding_lifecycle ADD COLUMN IF NOT EXISTS recast_by   TEXT;
ALTER TABLE finding_lifecycle ADD COLUMN IF NOT EXISTS recast_at   TIMESTAMPTZ;

-- Retire the old status column (drops its CHECK + index dependency automatically).
DROP INDEX IF EXISTS finding_lifecycle_status_idx;
ALTER TABLE finding_lifecycle DROP COLUMN status;

CREATE INDEX IF NOT EXISTS finding_lifecycle_disposition_idx ON finding_lifecycle (disposition);
