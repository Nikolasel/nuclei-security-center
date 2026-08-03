-- Schedules align name uniqueness with the other named config resources
-- (targets, template sets, scan policies, service accounts): the old inline
-- case-sensitive column UNIQUE from 0007 let "Nightly scan" and "nightly scan"
-- coexist. Replace it with a unique index on lower(name).
--
-- Collision policy: before the new index is built, any existing rows that
-- differ only in case are resolved deterministically. The earliest-created row
-- (ties broken by id) keeps its name; every later row in the group is renamed
-- by appending " (N)" where N is its 1-based rank within the group (so the
-- first duplicate in a group becomes "nightly scan (2)"), repeating until each
-- lowercase name is distinct. No schedule is deleted and scan provenance
-- (scans.schedule_id → schedules.id) is untouched; these are alpha-era config
-- rows, so renaming is cheaper than failing to apply.
DO $$
DECLARE
    renamed_rows integer;
BEGIN
    LOOP
        WITH ranked AS (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY lower(name)
                       ORDER BY created_at, id
                   ) AS rn
              FROM schedules
        )
        UPDATE schedules s
           SET name = s.name || ' (' || r.rn || ')'
          FROM ranked r
         WHERE r.id = s.id
           AND r.rn > 1;
        GET DIAGNOSTICS renamed_rows = ROW_COUNT;
        EXIT WHEN renamed_rows = 0;
    END LOOP;
END
$$;

-- Drop the case-sensitive column constraint (its backing index goes with it)
-- and rebuild uniqueness on lower(name), matching the other named resources.
ALTER TABLE schedules DROP CONSTRAINT IF EXISTS schedules_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS schedules_name_key ON schedules (lower(name));