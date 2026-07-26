-- PostgreSQL JSONB rejects the otherwise-valid JSON string escape \u0000. Keep
-- the original Nuclei JSONL line in TEXT (where its printable escape is safe)
-- and use findings.raw only as a queryable, NUL-sanitized JSONB projection.
-- Historical JSONB rows cannot be restored byte-for-byte, so seed their raw
-- line with PostgreSQL's normalized JSON text.

ALTER TABLE findings ADD COLUMN raw_line TEXT;
UPDATE findings SET raw_line = raw::text;
ALTER TABLE findings ALTER COLUMN raw_line SET NOT NULL;
