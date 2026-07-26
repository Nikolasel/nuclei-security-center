-- PostgreSQL JSONB rejects the otherwise-valid JSON string escape \u0000. Keep
-- new Nuclei JSONL lines in TEXT (with invalid UTF-8 normalized by the ingest
-- path) and use findings.raw as a queryable, NUL-sanitized JSONB projection.
--
-- This column deliberately stays nullable and historical rows are not
-- backfilled. Avoiding a full findings-table rewrite keeps startup migration
-- bounded, and an old binary remains safe to roll back because it may still
-- insert rows without raw_line. Readers fall back to raw::text for such rows.

ALTER TABLE findings ADD COLUMN raw_line TEXT;
