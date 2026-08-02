-- Dynamic template sets may exclude selected catalog template ids while still
-- following future active-catalog additions. Exact-set membership remains
-- driven exclusively by template_set_members.
CREATE TABLE IF NOT EXISTS template_set_exclusions (
    template_set_id UUID NOT NULL REFERENCES template_sets(id) ON DELETE CASCADE,
    template_id     TEXT NOT NULL REFERENCES templates(id)     ON DELETE CASCADE,
    added_by        TEXT,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (template_set_id, template_id)
);

CREATE INDEX IF NOT EXISTS template_set_exclusions_template_idx
    ON template_set_exclusions (template_id);
