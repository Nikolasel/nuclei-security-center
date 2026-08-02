-- Dynamic template sets may exclude selected catalog template ids while still
-- following future active-catalog additions. Exact-set membership remains
-- driven exclusively by template_set_members.
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
