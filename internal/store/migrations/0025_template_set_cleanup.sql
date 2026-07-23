-- Finish the template-set contract cutover (#85). Preserve the POC selector for
-- the one-time conversion action, then remove the filter columns: new and
-- converted sets are driven only by template_set_members.

ALTER TABLE template_sets
    ADD COLUMN IF NOT EXISTS legacy_filter_snapshot JSONB;

UPDATE template_sets
SET legacy_filter_snapshot = jsonb_build_object(
        'git_ref', COALESCE(git_ref, ''),
        'severities', severities,
        'tags', tags,
        'paths', paths
    )
WHERE legacy_filter
  AND legacy_filter_snapshot IS NULL;

ALTER TABLE template_sets
    DROP COLUMN IF EXISTS git_ref,
    DROP COLUMN IF EXISTS severities,
    DROP COLUMN IF EXISTS tags,
    DROP COLUMN IF EXISTS paths;
