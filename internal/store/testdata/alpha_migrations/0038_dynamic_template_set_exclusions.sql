-- Template sets have three explicit resolution modes:
--   exact   — stored template_set_members
--   all     — every active catalog template
--   exclude — every active catalog template except template_set_exclusions
-- Replace the old boolean before creating the exclusion table so API and
-- exports cannot conflate "all" with "all except these".
ALTER TABLE template_sets
    ADD COLUMN mode TEXT;

UPDATE template_sets
SET mode = CASE WHEN dynamic_all THEN 'all' ELSE 'exact' END;

ALTER TABLE template_sets
    ALTER COLUMN mode SET DEFAULT 'exact',
    ALTER COLUMN mode SET NOT NULL,
    ADD CONSTRAINT template_sets_mode_check
        CHECK (mode IN ('exact', 'all', 'exclude')),
    DROP COLUMN dynamic_all;

CREATE TABLE IF NOT EXISTS template_set_exclusions (
    template_set_id UUID NOT NULL REFERENCES template_sets(id) ON DELETE CASCADE,
    -- Unlike exact membership, deleting this referenced template would make a
    -- deny-list fail open, so the operator must remove the exclusion first.
    template_id     TEXT NOT NULL
        CONSTRAINT template_set_exclusions_template_id_fkey
        REFERENCES templates(id) ON DELETE RESTRICT,
    added_by        TEXT,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (template_set_id, template_id)
);

CREATE INDEX IF NOT EXISTS template_set_exclusions_template_idx
    ON template_set_exclusions (template_id);
