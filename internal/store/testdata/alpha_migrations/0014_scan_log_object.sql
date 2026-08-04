-- Scanner execution-log archive (#94). Nuclei's own stdout/stderr for a run
-- (interleaved -stats-json progress, template-load warnings, host-level errors)
-- is archived per scan to the same S3-compatible bucket as raw.jsonl, as a
-- separate object (log.txt). log_object_key holds that archive's bucket key, or
-- NULL when a scan predates the feature or the best-effort upload was
-- skipped/failed. The API exposes only a has_log boolean, never the key —
-- mirroring raw_object_key (migration 0009).

ALTER TABLE scans ADD COLUMN IF NOT EXISTS log_object_key TEXT;
