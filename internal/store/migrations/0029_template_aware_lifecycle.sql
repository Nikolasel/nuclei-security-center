-- Detection state is derived against the latest completed scan on the target
-- that included the finding's concrete template id (#88). The lifecycle query
-- walks a target's completed scans newest-first until it finds matching
-- template coverage, so this partial index keeps that correlated lookup bounded
-- to the relevant target history.

CREATE INDEX IF NOT EXISTS scans_complete_target_created_idx
    ON scans (target_id, created_at DESC)
    WHERE state = 'complete';
