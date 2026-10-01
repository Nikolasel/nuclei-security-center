-- Per-policy scan digest notification settings (#335).
-- Nullable policy columns inherit the deployment default (SMTP_TO, all
-- severities, digest on). Resolved values are snapshotted onto scans at
-- dispatch because MarkComplete derives the digest later and
-- scans.scan_policy_id is ON DELETE SET NULL.

ALTER TABLE scan_policies
    ADD COLUMN notify_digest_enabled boolean,
    ADD COLUMN notify_recipients text[],
    ADD COLUMN notify_min_severity text;

ALTER TABLE scan_policies
    ADD CONSTRAINT scan_policies_notify_min_severity_check
        CHECK (notify_min_severity IS NULL OR notify_min_severity IN ('info', 'low', 'medium', 'high', 'critical'));

COMMENT ON COLUMN scan_policies.notify_digest_enabled IS 'NULL inherits digest-on; false mutes completed-scan digest mail (failed mail stays global)';
COMMENT ON COLUMN scan_policies.notify_recipients IS 'NULL/empty inherits SMTP_TO for digest mail';
COMMENT ON COLUMN scan_policies.notify_min_severity IS 'NULL/empty includes every severity; a floor drops lower named severities from digest counts and the finding list';

ALTER TABLE scans
    ADD COLUMN notify_digest_enabled boolean NOT NULL DEFAULT TRUE,
    ADD COLUMN notify_recipients text[],
    ADD COLUMN notify_min_severity text;

ALTER TABLE scans
    ADD CONSTRAINT scans_notify_min_severity_check
        CHECK (notify_min_severity IS NULL OR notify_min_severity IN ('info', 'low', 'medium', 'high', 'critical'));

COMMENT ON COLUMN scans.notify_digest_enabled IS 'Digest enablement resolved from the policy at dispatch';
COMMENT ON COLUMN scans.notify_recipients IS 'Digest recipients resolved at dispatch; NULL means SMTP_TO';
COMMENT ON COLUMN scans.notify_min_severity IS 'Digest severity floor resolved at dispatch; NULL means no floor';
