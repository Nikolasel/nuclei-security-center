-- Surface Nuclei result identity as display/filter columns (#315).
--
-- Lifecycle identity remains the hashed result_discriminator; these columns are
-- the plain matcher / extractor / extracted-results values so the UI, filters,
-- and projected exports can distinguish two results that share a template_id
-- and matched_at. They are not part of the dedup key.
--
-- Historical rows are backfilled from findings.raw (the NUL-safe JSONB
-- projection). Malformed extracted-results arrays are treated as empty, matching
-- ingest's discriminator parser. Rows whose raw JSON never carried these fields
-- stay as empty string / empty array (not NULL).

ALTER TABLE findings
    ADD COLUMN matcher_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN extractor_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN extracted_results TEXT[] NOT NULL DEFAULT '{}'::text[];

ALTER TABLE finding_lifecycle
    ADD COLUMN matcher_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN extractor_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN extracted_results TEXT[] NOT NULL DEFAULT '{}'::text[];

COMMENT ON COLUMN findings.matcher_name IS 'Nuclei matcher-name for display/filter; empty when absent';
COMMENT ON COLUMN findings.extractor_name IS 'Nuclei extractor-name for display/filter; empty when absent';
COMMENT ON COLUMN findings.extracted_results IS 'Nuclei extracted-results in source order; empty when absent or malformed';
COMMENT ON COLUMN finding_lifecycle.matcher_name IS 'Nuclei matcher-name for display/filter; empty when absent';
COMMENT ON COLUMN finding_lifecycle.extractor_name IS 'Nuclei extractor-name for display/filter; empty when absent';
COMMENT ON COLUMN finding_lifecycle.extracted_results IS 'Nuclei extracted-results in source order; empty when absent or malformed';

UPDATE findings
   SET matcher_name = CASE
           WHEN jsonb_typeof(raw -> 'matcher-name') = 'string'
           THEN raw ->> 'matcher-name'
           ELSE ''
       END,
       extractor_name = CASE
           WHEN jsonb_typeof(raw -> 'extractor-name') = 'string'
           THEN raw ->> 'extractor-name'
           ELSE ''
       END,
       extracted_results = CASE
           WHEN jsonb_typeof(raw -> 'extracted-results') = 'array'
            AND NOT EXISTS (
                SELECT 1
                  FROM jsonb_array_elements(raw -> 'extracted-results') item
                 WHERE jsonb_typeof(item) <> 'string'
            )
           THEN ARRAY(SELECT jsonb_array_elements_text(raw -> 'extracted-results'))
           ELSE '{}'::text[]
       END;

UPDATE finding_lifecycle AS l
   SET matcher_name = o.matcher_name,
       extractor_name = o.extractor_name,
       extracted_results = o.extracted_results
  FROM findings AS o
 WHERE o.id = l.latest_occurrence_id;
