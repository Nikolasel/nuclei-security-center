-- Promote the triage dimensions that only lived in the raw JSONL (CVE ids and
-- tags) to first-class, indexed columns so the findings list can filter on them
-- efficiently. name/severity/host/template_id are already columns.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS cve  TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

-- Backfill existing rows from the preserved raw payload. Guard on jsonb_typeof
-- so a missing/non-array path yields '{}' instead of erroring.
UPDATE findings SET
    cve = CASE WHEN jsonb_typeof(raw #> '{info,classification,cve-id}') = 'array'
               THEN ARRAY(SELECT jsonb_array_elements_text(raw #> '{info,classification,cve-id}'))
               ELSE '{}' END,
    tags = CASE WHEN jsonb_typeof(raw #> '{info,tags}') = 'array'
                THEN ARRAY(SELECT jsonb_array_elements_text(raw #> '{info,tags}'))
                ELSE '{}' END;

CREATE INDEX IF NOT EXISTS findings_cve_idx  ON findings USING GIN (cve);
CREATE INDEX IF NOT EXISTS findings_tags_idx ON findings USING GIN (tags);
