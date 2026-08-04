-- A scan policy describes HOW to scan (templates + execution/discovery knobs).
-- The approved target describes WHAT to scan and is selected independently by
-- ad-hoc dispatches or stored on schedules (#137).
--
-- Preserve every existing schedule by copying the target from its current
-- policy before removing the policy-owned reference. Historical scans already
-- record their resolved target_id and need no rewrite.
ALTER TABLE schedules
    ADD COLUMN target_id UUID;

UPDATE schedules schedule
   SET target_id = policy.target_id
  FROM scan_policies policy
 WHERE policy.id = schedule.scan_policy_id;

ALTER TABLE schedules
    ALTER COLUMN target_id SET NOT NULL,
    ADD CONSTRAINT schedules_target_id_fkey
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE;

CREATE INDEX schedules_target_id_idx ON schedules (target_id);

ALTER TABLE scan_policies
    DROP COLUMN target_id;

COMMENT ON TABLE scan_policies IS
    'Reusable target-independent scan configuration: template set plus Nuclei/discovery knobs';
COMMENT ON COLUMN schedules.target_id IS
    'Approved stored target selected independently from the reusable scan policy';
