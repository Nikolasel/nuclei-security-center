-- findings.target_id is a denormalized copy of its owning scan's scope. The
-- lifecycle read path keeps that copy for indexed target projection/filtering,
-- while coverage logic reads scans.target_id as the authority. Constrain the
-- targeted case so those two efficient representations cannot diverge.
--
-- MATCH SIMPLE deliberately permits (scan_id, NULL) for ad-hoc scans. When a
-- stored target is deleted, scans.target_id becomes NULL and ON UPDATE CASCADE
-- keeps its surviving occurrence history consistent.
ALTER TABLE scans
    ADD CONSTRAINT scans_id_target_key UNIQUE (id, target_id);

ALTER TABLE findings
    ADD CONSTRAINT findings_scan_scope_fk
    FOREIGN KEY (scan_id, target_id)
    REFERENCES scans (id, target_id)
    MATCH SIMPLE
    ON UPDATE CASCADE
    ON DELETE CASCADE;

COMMENT ON COLUMN findings.target_id IS
    'Denormalized scan scope for indexed lifecycle projection/filtering; constrained to scans.target_id when non-NULL';
