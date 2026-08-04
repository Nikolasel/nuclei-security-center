-- Keep the latest completed scan that could have observed each lifecycle
-- finding as a compact evidence pointer (#88). Deriving this by probing every
-- scan's large JSONB template array for every lifecycle row made list/count
-- latency grow with both histories. MarkComplete advances the pointer once per
-- scan; lifecycle reads remain ordinary indexed row reads.

ALTER TABLE finding_lifecycle
    ADD COLUMN last_covering_scan UUID REFERENCES scans(id) ON DELETE SET NULL;

CREATE INDEX finding_lifecycle_last_covering_scan_idx
    ON finding_lifecycle (last_covering_scan)
    WHERE last_covering_scan IS NOT NULL;

CREATE INDEX finding_lifecycle_target_template_idx
    ON finding_lifecycle (target_id, template_id)
    WHERE target_id IS NOT NULL;

-- Backfill both the evidence pointer and mitigation-cycle count from surviving
-- history. Concrete ids are authoritative. For pre-catalog scans, observing a
-- template anywhere proves that template ran scan-wide; a legacy absence
-- without that positive signal proves nothing. Guard malformed historical JSON
-- so a scalar template_ids value cannot abort migration or later repair.
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
     WHERE scans.state = 'complete' AND scans.target_id IS NOT NULL
    UNION
    SELECT scans.id, scans.target_id, scans.created_at, findings.template_id
      FROM scans
      JOIN findings ON findings.scan_id = scans.id
     WHERE scans.state = 'complete' AND scans.target_id IS NOT NULL
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
      JOIN scan_coverage coverage
        ON coverage.target_id = lifecycle.target_id
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
),
resolved AS (
    SELECT lifecycle.id AS lifecycle_id,
           stats.last_covering_scan,
           coalesce(stats.times_mitigated, 0) AS times_mitigated
      FROM finding_lifecycle lifecycle
      LEFT JOIN stats ON stats.lifecycle_id = lifecycle.id
     WHERE lifecycle.target_id IS NOT NULL
)
UPDATE finding_lifecycle lifecycle
   SET last_covering_scan = resolved.last_covering_scan,
       times_mitigated = resolved.times_mitigated
  FROM resolved
 WHERE lifecycle.id = resolved.lifecycle_id;

-- Scan deletion repair still walks one target's history oldest-first.
CREATE INDEX scans_complete_target_created_idx
    ON scans (target_id, created_at)
    WHERE state = 'complete';
