-- Explicit template-set membership (#85). A template set becomes a curated list
-- of individual catalog templates (upstream or custom), replacing the POC's
-- "filter over the community repo" model. This migration is ADDITIVE: the legacy
-- git_ref/severities/tags/paths columns stay for now so dispatch keeps working;
-- the scan-contract cutover slice removes them and switches dispatch to members.

CREATE TABLE IF NOT EXISTS template_set_members (
    template_set_id UUID NOT NULL REFERENCES template_sets(id) ON DELETE CASCADE,
    template_id     TEXT NOT NULL REFERENCES templates(id)     ON DELETE CASCADE,
    added_by        TEXT,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (template_set_id, template_id)
);

-- Reverse lookup: "which sets contain this template" (used when a template is
-- deleted/tombstoned, and for the catalog UI's membership badges).
CREATE INDEX IF NOT EXISTS template_set_members_template_idx
    ON template_set_members (template_id);

-- legacy_filter flags the pre-existing POC rows so the UI can render them
-- read-only with a "convert to explicit selection" affordance. Every row that
-- exists at migration time is filter-style, so flag them all; new member-based
-- sets are created with legacy_filter = false (the column default).
ALTER TABLE template_sets
    ADD COLUMN IF NOT EXISTS legacy_filter BOOLEAN NOT NULL DEFAULT false;

UPDATE template_sets SET legacy_filter = true;
