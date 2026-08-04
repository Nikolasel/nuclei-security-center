-- Phase 2 (slice 2): cron schedules. A schedule ties a target (+ optional
-- template set) to a cron expression; the backend ticker dispatches the ones
-- that are due. Postgres is the source of truth (survives restart, persists
-- enable/disable, holds next_run_at); the cron library only computes the next
-- fire time. next_run_at is maintained in the backend, so no cron logic lives
-- in SQL.

CREATE TABLE IF NOT EXISTS schedules (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    target_id       UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    template_set_id UUID REFERENCES template_sets(id) ON DELETE SET NULL,
    cron            TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    next_run_at     TIMESTAMPTZ,
    last_run_at     TIMESTAMPTZ,
    last_scan_id    UUID REFERENCES scans(id) ON DELETE SET NULL,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The ticker's hot path: enabled schedules whose next fire time has arrived.
CREATE INDEX IF NOT EXISTS schedules_due_idx ON schedules (next_run_at) WHERE enabled;

-- Scan provenance: adhoc (a user clicked "run") vs schedule (the ticker fired).
-- schedule_id keeps a scan traceable to the schedule that produced it; deleting
-- the schedule nulls the link but never touches scan history.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'adhoc';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS schedule_id UUID REFERENCES schedules(id) ON DELETE SET NULL;
