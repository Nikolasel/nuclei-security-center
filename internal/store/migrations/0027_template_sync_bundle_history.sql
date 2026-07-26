-- Record the canonical active-catalog bundle state on each completed upstream
-- sync attempt. The upstream Git commit alone is insufficient for matching a
-- scanner node: custom templates are part of the pushed full-catalog bundle.
-- Existing history remains NULL because prior catalog states cannot be
-- reconstructed losslessly from the current templates table.

ALTER TABLE template_sync_runs
    ADD COLUMN templates_commit TEXT,
    ADD COLUMN template_count INTEGER CHECK (template_count >= 0);
