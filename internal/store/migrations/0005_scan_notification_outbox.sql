-- Per-scan notification outbox (#321) and per-policy digest settings (#335).
-- One row per (scan_id, kind) records the derived digest or failure payload at
-- the terminal-state write so a backend restart cannot send the same mail twice.
-- claimed_at is set immediately before SMTP; a send failure leaves the row
-- claimed (at-most-once, best-effort).
--
-- Nullable policy columns inherit the deployment default (SMTP_TO, all
-- severities, digest on). Resolved values are snapshotted onto scans at
-- dispatch because MarkComplete derives the digest later and
-- scans.scan_policy_id is ON DELETE SET NULL.

CREATE TABLE scan_notification_outbox (
    scan_id    UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('digest', 'failed')),
    payload    JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at TIMESTAMPTZ,
    PRIMARY KEY (scan_id, kind)
);

COMMENT ON TABLE scan_notification_outbox IS 'At-most-once scan digest / failure mail payloads; not a delivery retry queue';
COMMENT ON COLUMN scan_notification_outbox.kind IS 'digest = completed-scan deltas; failed = node/backend failure (not operator cancel)';
COMMENT ON COLUMN scan_notification_outbox.claimed_at IS 'Set before SMTP; NULL means the completing process has not yet attempted send';

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
