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
-- choice by attaching them to one explicit dynamic set. Only create the
-- migration set when such policies exist. Never reuse a row by display name:
-- an exact user-curated set may legitimately be named "All templates", and
-- converting it would silently discard its stored membership.
DO $$
DECLARE
    all_templates_id   UUID := '00000000-0000-4000-8000-000000000085';
    all_templates_name TEXT := 'All templates';
    name_suffix        INTEGER := 0;
BEGIN
    IF EXISTS (SELECT 1 FROM scan_policies WHERE template_set_id IS NULL) THEN
        IF EXISTS (SELECT 1 FROM template_sets WHERE id = all_templates_id) THEN
            RAISE EXCEPTION
                'reserved dynamic template-set id % is already in use',
                all_templates_id;
        END IF;

        -- The case-insensitive name index is unique. Preserve every existing
        -- row and choose a clear alternate label if a user already claimed the
        -- preferred name.
        WHILE EXISTS (
            SELECT 1 FROM template_sets WHERE lower(name) = lower(all_templates_name)
        ) LOOP
            name_suffix := name_suffix + 1;
            IF name_suffix = 1 THEN
                all_templates_name := 'All templates (dynamic)';
            ELSE
                all_templates_name := format(
                    'All templates (dynamic %s)', name_suffix
                );
            END IF;
        END LOOP;

        INSERT INTO template_sets (id, name, dynamic_all)
        VALUES (all_templates_id, all_templates_name, true);

        UPDATE scan_policies
        SET template_set_id = all_templates_id, updated_at = now()
        WHERE template_set_id IS NULL;
    END IF;
END $$;

ALTER TABLE scan_policies
    DROP CONSTRAINT IF EXISTS scan_policies_template_set_id_fkey,
    ALTER COLUMN template_set_id SET NOT NULL,
    ADD CONSTRAINT scan_policies_template_set_id_fkey
        FOREIGN KEY (template_set_id) REFERENCES template_sets(id) ON DELETE RESTRICT;

ALTER TABLE template_sets
    DROP COLUMN legacy_filter,
    DROP COLUMN legacy_filter_snapshot;
