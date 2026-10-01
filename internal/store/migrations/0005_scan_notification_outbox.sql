-- Per-scan notification outbox (#321). One row per (scan_id, kind) records the
-- derived digest or failure payload at the terminal-state write so a backend
-- restart cannot send the same mail twice. claimed_at is set immediately before
-- SMTP; a send failure leaves the row claimed (at-most-once, best-effort).

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
