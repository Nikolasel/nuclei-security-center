-- Schedules align name uniqueness with the other named config resources
-- (targets, template sets, scan policies, service accounts): the old inline
-- case-sensitive column UNIQUE from 0007 let "Nightly scan" and "nightly scan"
-- coexist. Replace it with a unique index on lower(name).
--
-- Collision policy: any existing rows that differ only in case are resolved
-- deterministically. The earliest-created row (ties broken by id) keeps its
-- name; every later row in the group is renamed by appending " (N)" where N is
-- its 1-based rank within the group. Renames are re-ranked until every
-- lowercase name is distinct. Because a rename can land on a generated name
-- another row already holds (e.g. a hand-suffixed "weekly scan (2)"), the
-- cascade can also re-rename rows that never had a case-duplicate of their own
-- — a plain name change is not a sign of corruption. No schedule is deleted and
-- scan provenance (scans.schedule_id → schedules.id) is untouched; these are
-- alpha-era config rows, so renaming is cheaper than failing to apply.

-- Drop the case-sensitive column constraint (its backing index goes with it)
-- BEFORE resolving collisions: every UPDATE in the loop below must not be
-- checked against the very constraint being replaced. Renaming "weekly scan"
-- to "weekly scan (2)" while a row of that exact name exists would otherwise
-- abort the whole migration on the case it exists to clean up.
ALTER TABLE schedules DROP CONSTRAINT IF EXISTS schedules_name_key;

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

-- Rebuild uniqueness on lower(name), matching the other named resources. No
-- IF NOT EXISTS: the name was just freed by the DROP above, and silently
-- reusing a differently-shaped index that happened to carry this name would
-- leave case-insensitive uniqueness unenforced without any error.
CREATE UNIQUE INDEX schedules_name_key ON schedules (lower(name));
