-- Record source finding records that were safely skipped during backend ingest.
-- Operational/database errors remain fatal and are never counted here.

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS skipped_finding_count INTEGER NOT NULL DEFAULT 0
    CHECK (skipped_finding_count >= 0);
