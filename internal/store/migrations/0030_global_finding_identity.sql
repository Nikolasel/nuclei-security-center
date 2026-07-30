-- Global finding identity and exact scan occurrences (#120).
--
-- A scan result remains an immutable occurrence owned by one scan/target.
-- finding_lifecycle becomes the global triage entity keyed by:
--
--   (template_id, matched_at, stable result discriminator)
--
-- Thus repeated observations merge across scans and target records, while a
-- template that intentionally emits distinct matcher/extractor/extracted
-- results at one endpoint keeps independent lifecycle entities.
--
-- Operational note: this migration is intentionally atomic, but it rewrites
-- every linked occurrence and rebuilds lifecycle/coverage state. On a large
-- history it can hold table locks, generate substantial WAL, and extend backend
-- startup; plan the upgrade in a maintenance window. Existing lifecycle ids
-- survive only for exact 1:1 old→new identities. Genuine splits and merges get
-- fresh ids because retaining one parent's id would make old links ambiguous.

ALTER TABLE findings
    ADD COLUMN result_discriminator TEXT NOT NULL DEFAULT '';

ALTER TABLE finding_lifecycle
    ADD COLUMN result_discriminator TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN findings.result_discriminator IS
    'SHA-256 of stable matcher/extractor/extracted-result identity; empty for ordinary findings';
COMMENT ON COLUMN finding_lifecycle.result_discriminator IS
    'SHA-256 of stable matcher/extractor/extracted-result identity; empty for ordinary findings';

-- Keep historical backfill and Go ingestion byte-identical:
--   m<len>:<matcher>e<len>:<extractor>x<count>:<len>:<result>...
-- Result strings are sorted bytewise and duplicates remain.
CREATE FUNCTION nsc_finding_result_discriminator(source JSONB)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
WITH parts AS (
    SELECT
        CASE WHEN jsonb_typeof(source -> 'matcher-name') = 'string'
             THEN source ->> 'matcher-name' ELSE '' END AS matcher_name,
        CASE WHEN jsonb_typeof(source -> 'extractor-name') = 'string'
             THEN source ->> 'extractor-name' ELSE '' END AS extractor_name,
        CASE
            WHEN jsonb_typeof(source -> 'extracted-results') = 'array'
             AND NOT EXISTS (
                 SELECT 1
                   FROM jsonb_array_elements(source -> 'extracted-results') item
                  WHERE jsonb_typeof(item) <> 'string'
             )
            THEN source -> 'extracted-results'
            ELSE '[]'::jsonb
        END AS extracted_results
),
canonical AS (
    SELECT matcher_name,
           extractor_name,
           extracted_results,
           'm' || octet_length(matcher_name)::text || ':' || matcher_name ||
           'e' || octet_length(extractor_name)::text || ':' || extractor_name ||
           'x' || (
               SELECT count(*)::text || ':' ||
                      coalesce(
                          string_agg(
                              octet_length(value)::text || ':' || value,
                              '' ORDER BY value COLLATE "C"
                          ),
                          ''
                      )
                 FROM jsonb_array_elements_text(extracted_results) result(value)
           ) AS identity_bytes
      FROM parts
)
SELECT CASE
           WHEN matcher_name = '' AND extractor_name = ''
            AND jsonb_array_length(extracted_results) = 0
           THEN ''
           ELSE encode(sha256(convert_to(identity_bytes, 'UTF8')), 'hex')
       END
  FROM canonical
$$;

-- PostgreSQL TEXT cannot contain NUL. Remove exactly the remaining ASCII C0
-- range plus DEL, matching sanitizeKeyComponent in lifecycle.go without the
-- locale-dependent C1 behavior of the POSIX [[:cntrl:]] class.
CREATE FUNCTION nsc_finding_key_part(value TEXT)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
SELECT translate(
    coalesce(value, ''),
    (SELECT string_agg(chr(codepoint), '' ORDER BY codepoint)
       FROM (
           SELECT generate_series(1, 31) AS codepoint
           UNION ALL SELECT 127
       ) controls),
    ''
)
$$;

-- Occurrences still point to their old target-scoped lifecycle parents here.
-- Preserve that mapping for analyst-state conflict resolution before relinking.
-- Rows already unlinked by scan-deletion lifecycle repair remain deliberately
-- untracked; do not resurrect them during the rebuild.
CREATE TEMP TABLE nsc_eligible_occurrences_0030 AS
SELECT id
  FROM findings
 WHERE finding_id IS NOT NULL;

WITH identity AS (
    SELECT id, nsc_finding_result_discriminator(raw) AS discriminator
      FROM findings
)
UPDATE findings occurrence
   SET result_discriminator = identity.discriminator,
       dedup_key =
           nsc_finding_key_part(occurrence.template_id) || E'\x1f' ||
           nsc_finding_key_part(occurrence.matched_at) ||
           CASE WHEN identity.discriminator = '' THEN ''
                ELSE E'\x1f' || identity.discriminator END
  FROM identity
 WHERE identity.id = occurrence.id;

CREATE TEMP TABLE nsc_variant_parents_0030 AS
SELECT DISTINCT occurrence.dedup_key, occurrence.finding_id AS old_lifecycle_id
  FROM findings occurrence
  JOIN nsc_eligible_occurrences_0030 eligible ON eligible.id = occurrence.id;

-- Build complete replacement rows while the old lifecycle table still carries
-- its target-scoped analyst overlays. Disposition and recast choose their most
-- recent actions independently; a recent explicit clear therefore wins too.
CREATE TEMP TABLE nsc_global_lifecycle_0030 AS
WITH latest AS (
    SELECT DISTINCT ON (occurrence.dedup_key)
           occurrence.dedup_key,
           occurrence.result_discriminator,
           occurrence.template_id,
           occurrence.name,
           occurrence.severity,
           occurrence.host,
           occurrence.matched_at,
           occurrence.type,
           occurrence.cve,
           occurrence.tags,
           occurrence.scan_id AS last_seen_scan,
           occurrence.created_at AS last_seen_at,
           occurrence.id AS latest_occurrence_id
      FROM findings occurrence
      JOIN nsc_eligible_occurrences_0030 eligible ON eligible.id = occurrence.id
     ORDER BY occurrence.dedup_key, occurrence.created_at DESC, occurrence.id DESC
),
first_seen AS (
    SELECT DISTINCT ON (occurrence.dedup_key)
           occurrence.dedup_key,
           occurrence.scan_id AS first_seen_scan,
           occurrence.created_at AS first_seen_at
      FROM findings occurrence
      JOIN nsc_eligible_occurrences_0030 eligible ON eligible.id = occurrence.id
     ORDER BY occurrence.dedup_key, occurrence.created_at, occurrence.id
)
SELECT latest.*,
       first_seen.first_seen_scan,
       first_seen.first_seen_at,
       coalesce(disposition.disposition, 'none') AS disposition,
       disposition.accept_expires_at,
       disposition.disposition_note,
       disposition.disposition_by,
       disposition.disposition_at,
       recast.recast_severity,
       recast.recast_note,
       recast.recast_by,
       recast.recast_at,
       CASE
           WHEN (
               SELECT count(DISTINCT parent.old_lifecycle_id)
                 FROM nsc_variant_parents_0030 parent
                WHERE parent.dedup_key = latest.dedup_key
           ) = 1
            AND (
               SELECT count(DISTINCT sibling.dedup_key)
                 FROM nsc_variant_parents_0030 sibling
                WHERE sibling.old_lifecycle_id = (
                    SELECT min(parent.old_lifecycle_id)
                      FROM nsc_variant_parents_0030 parent
                     WHERE parent.dedup_key = latest.dedup_key
                )
           ) = 1
           THEN (
               SELECT min(parent.old_lifecycle_id)
                 FROM nsc_variant_parents_0030 parent
                WHERE parent.dedup_key = latest.dedup_key
           )
       END AS preserved_id
  FROM latest
  JOIN first_seen USING (dedup_key)
  LEFT JOIN LATERAL (
      SELECT lifecycle.disposition,
             lifecycle.accept_expires_at,
             lifecycle.disposition_note,
             lifecycle.disposition_by,
             lifecycle.disposition_at
        FROM nsc_variant_parents_0030 parent
        JOIN finding_lifecycle lifecycle ON lifecycle.id = parent.old_lifecycle_id
       WHERE parent.dedup_key = latest.dedup_key
       ORDER BY lifecycle.disposition_at DESC NULLS LAST, lifecycle.id DESC
       LIMIT 1
  ) disposition ON true
  LEFT JOIN LATERAL (
      SELECT lifecycle.recast_severity,
             lifecycle.recast_note,
             lifecycle.recast_by,
             lifecycle.recast_at
        FROM nsc_variant_parents_0030 parent
        JOIN finding_lifecycle lifecycle ON lifecycle.id = parent.old_lifecycle_id
       WHERE parent.dedup_key = latest.dedup_key
       ORDER BY lifecycle.recast_at DESC NULLS LAST, lifecycle.id DESC
       LIMIT 1
  ) recast ON true;

-- Decouple occurrences, replace the target-scoped lifecycle rows with global
-- rows, then reconnect each immutable occurrence by its new global key.
UPDATE findings occurrence
   SET finding_id = NULL
  FROM nsc_eligible_occurrences_0030 eligible
 WHERE eligible.id = occurrence.id;
DELETE FROM finding_lifecycle;

INSERT INTO finding_lifecycle (
    id, dedup_key, result_discriminator, template_id, name, severity, host,
    matched_at, type, cve, tags,
    first_seen_scan, first_seen_at, last_seen_scan, last_seen_at,
    latest_occurrence_id, disposition, accept_expires_at, recast_severity,
    times_mitigated, disposition_note, disposition_by, disposition_at,
    recast_note, recast_by, recast_at, last_covering_scan
)
SELECT coalesce(
           preserved_id,
           nextval(pg_get_serial_sequence('finding_lifecycle', 'id'))
       ),
       dedup_key,
       result_discriminator,
       template_id,
       name,
       severity,
       host,
       matched_at,
       type,
       cve,
       tags,
       first_seen_scan,
       first_seen_at,
       last_seen_scan,
       last_seen_at,
       latest_occurrence_id,
       disposition,
       accept_expires_at,
       recast_severity,
       0,
       disposition_note,
       disposition_by,
       disposition_at,
       recast_note,
       recast_by,
       recast_at,
       NULL
  FROM nsc_global_lifecycle_0030;

UPDATE findings occurrence
   SET finding_id = lifecycle.id
  FROM finding_lifecycle lifecycle,
       nsc_eligible_occurrences_0030 eligible
 WHERE eligible.id = occurrence.id
   AND lifecycle.dedup_key = occurrence.dedup_key;

-- Global lifecycle rows no longer own one target. Target filtering and coverage
-- use immutable occurrence provenance instead.
ALTER TABLE finding_lifecycle DROP COLUMN target_id;

CREATE INDEX finding_lifecycle_template_idx
    ON finding_lifecycle (template_id);
CREATE INDEX IF NOT EXISTS finding_lifecycle_last_covering_scan_idx
    ON finding_lifecycle (last_covering_scan)
    WHERE last_covering_scan IS NOT NULL;
CREATE INDEX findings_finding_target_idx
    ON findings (finding_id, target_id);

-- Recompute comparison evidence and mitigation cycles for each global result.
-- A scan participates only when its target/ad-hoc scope has observed that
-- finding and it covered the template. This is target-independent aggregation,
-- but it deliberately does not claim to solve endpoint reachability (#91).
WITH scan_coverage AS (
    SELECT scans.id AS scan_id, scans.target_id, scans.created_at, ids.template_id
      FROM scans
      CROSS JOIN LATERAL jsonb_array_elements_text(
          CASE
              WHEN jsonb_typeof(scans.spec #> '{templates,template_ids}') = 'array'
              THEN scans.spec #> '{templates,template_ids}'
              ELSE '[]'::jsonb
          END
      ) AS ids(template_id)
     WHERE scans.state = 'complete'
    UNION
    SELECT scans.id, scans.target_id, scans.created_at, findings.template_id
      FROM scans
      JOIN findings ON findings.scan_id = scans.id
     WHERE scans.state = 'complete'
),
lifecycle_scopes AS (
    SELECT DISTINCT finding_id AS lifecycle_id, target_id
      FROM findings
     WHERE finding_id IS NOT NULL
),
timeline AS (
    SELECT lifecycle.id AS lifecycle_id,
           coverage.scan_id,
           coverage.created_at,
           EXISTS (
               SELECT 1
                 FROM findings observed
                WHERE observed.scan_id = coverage.scan_id
                  AND observed.finding_id = lifecycle.id
           ) AS present
      FROM finding_lifecycle lifecycle
      JOIN lifecycle_scopes scope ON scope.lifecycle_id = lifecycle.id
      JOIN scan_coverage coverage
        ON coverage.target_id IS NOT DISTINCT FROM scope.target_id
       AND coverage.template_id = lifecycle.template_id
),
transitions AS (
    SELECT timeline.*,
           lag(present, 1, false) OVER history AS previously_present,
           coalesce(
               bool_or(present) OVER (
                   PARTITION BY lifecycle_id
                   ORDER BY created_at, scan_id
                   ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
               ),
               false
           ) AS ever_previously_present
      FROM timeline
      WINDOW history AS (PARTITION BY lifecycle_id ORDER BY created_at, scan_id)
),
stats AS (
    SELECT lifecycle_id,
           (array_agg(scan_id ORDER BY created_at DESC, scan_id DESC))[1] AS last_covering_scan,
           count(*) FILTER (
               WHERE present AND NOT previously_present AND ever_previously_present
           )::integer AS times_mitigated
      FROM transitions
     GROUP BY lifecycle_id
)
UPDATE finding_lifecycle lifecycle
   SET last_covering_scan = stats.last_covering_scan,
       times_mitigated = stats.times_mitigated
  FROM stats
 WHERE lifecycle.id = stats.lifecycle_id;

DROP TABLE nsc_global_lifecycle_0030;
DROP TABLE nsc_variant_parents_0030;
DROP TABLE nsc_eligible_occurrences_0030;
DROP FUNCTION nsc_finding_result_discriminator(JSONB);
DROP FUNCTION nsc_finding_key_part(TEXT);
