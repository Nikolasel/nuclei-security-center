-- Repair the two historical shapes of 0029_template_aware_lifecycle.sql.
--
-- An early PR revision contained only scans_complete_target_created_idx. Some
-- development databases recorded that filename before the final revision added
-- last_covering_scan. Applied migration filenames are immutable now, so repair
-- the known drift in a separately tracked migration before 0030 uses the
-- evidence pointer.
ALTER TABLE finding_lifecycle
    ADD COLUMN IF NOT EXISTS last_covering_scan UUID REFERENCES scans(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS finding_lifecycle_last_covering_scan_idx
    ON finding_lifecycle (last_covering_scan)
    WHERE last_covering_scan IS NOT NULL;

-- The early revision used created_at DESC while the final revision used the
-- column's default ASC order. Recreate it so both starting states converge.
DROP INDEX IF EXISTS scans_complete_target_created_idx;
CREATE INDEX scans_complete_target_created_idx
    ON scans (target_id, created_at)
    WHERE state = 'complete';
