-- Alpha cutover: remove the retired legacy-filter compatibility path, make the
-- all-catalog choice an explicit dynamic template set, and require every scan
-- policy to reference a template set.

ALTER TABLE template_sets
    ADD COLUMN dynamic_all BOOLEAN NOT NULL DEFAULT false;

-- Legacy POC selectors are deliberately discarded rather than carried forward:
-- their compatibility/conversion path is no longer part of the alpha product.
-- Policies using them cannot be resolved safely, so delete those policies (and
-- their cascading schedules) before deleting the sets.
DELETE FROM scan_policies
WHERE template_set_id IN (
    SELECT id FROM template_sets WHERE legacy_filter
);
DELETE FROM template_sets WHERE legacy_filter;

-- Preserve existing policies that used NULL as the implicit "all templates"
-- choice by attaching them to one explicit dynamic set. Reuse a pre-existing
-- set named "All templates" if present; otherwise create the built-in row.
DO $$
DECLARE
    all_templates_id UUID;
BEGIN
    SELECT id INTO all_templates_id
    FROM template_sets
    WHERE lower(name) = 'all templates'
    LIMIT 1;

    IF all_templates_id IS NULL THEN
        all_templates_id := '00000000-0000-4000-8000-000000000085';
        INSERT INTO template_sets (id, name, dynamic_all)
        VALUES (all_templates_id, 'All templates', true);
    ELSE
        UPDATE template_sets
        SET dynamic_all = true, updated_at = now()
        WHERE id = all_templates_id;
        DELETE FROM template_set_members WHERE template_set_id = all_templates_id;
    END IF;

    UPDATE scan_policies
    SET template_set_id = all_templates_id, updated_at = now()
    WHERE template_set_id IS NULL;
END $$;

ALTER TABLE scan_policies
    DROP CONSTRAINT IF EXISTS scan_policies_template_set_id_fkey,
    ALTER COLUMN template_set_id SET NOT NULL,
    ADD CONSTRAINT scan_policies_template_set_id_fkey
        FOREIGN KEY (template_set_id) REFERENCES template_sets(id) ON DELETE RESTRICT;

ALTER TABLE template_sets
    DROP COLUMN legacy_filter,
    DROP COLUMN legacy_filter_snapshot;
