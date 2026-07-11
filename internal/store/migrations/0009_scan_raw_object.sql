-- Phase 3 (slice: object storage). The verbatim Nuclei out.jsonl for a scan is
-- archived to an S3-compatible bucket, not the DB (it's bulky, write-once
-- evidence). raw_object_key holds the bucket key of that archive, or NULL when a
-- scan predates archiving or the upload was skipped/failed (best-effort — the
-- projected findings in Postgres remain the system of record either way).

ALTER TABLE scans ADD COLUMN IF NOT EXISTS raw_object_key TEXT;
