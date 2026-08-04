-- Phase 0 schema: just enough to prove the dispatch -> run -> ingest loop.
-- Later phases add users, targets, template_sets, schedules, audit_log, and the
-- finding lifecycle columns (first_seen/last_seen/status).

CREATE TABLE IF NOT EXISTS scans (
    id               UUID PRIMARY KEY,
    node_scan_id     TEXT,
    state            TEXT NOT NULL,
    spec             JSONB NOT NULL,
    nuclei_version   TEXT,
    templates_commit TEXT,
    error            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS findings (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    template_id TEXT NOT NULL,
    name        TEXT,
    severity    TEXT,
    host        TEXT,
    matched_at  TEXT,
    type        TEXT,
    raw         JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings (scan_id);
CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings (severity);
