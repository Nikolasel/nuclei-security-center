-- First-class template catalog (#85). YAML is the sole authoritative template
-- body: parsed scalar fields are duplicated only for catalog filtering. Keeping
-- the original YAML makes imports, exports, and scanner bundles lossless.

CREATE TABLE IF NOT EXISTS templates (
    id             TEXT PRIMARY KEY,
    source         TEXT NOT NULL CHECK (source IN ('upstream', 'custom')),
    path           TEXT NOT NULL,
    yaml           TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    name           TEXT NOT NULL,
    author         TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    tags           TEXT[] NOT NULL DEFAULT '{}',
    upstream_ref   TEXT,
    revision       INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    availability   TEXT NOT NULL DEFAULT 'active' CHECK (availability IN ('active', 'unavailable')),
    created_by     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- DEFERRABLE so one sync transaction can rename paths freely: upstream file
    -- renames (and rename swaps, A->P2 while B->P1) transiently collide on
    -- (source, path) mid-loop; checking only at COMMIT lets the final state be
    -- consistent. Tombstoning also frees a path (see internal/store/templates.go),
    -- so a later, different id can reclaim a removed template's path.
    UNIQUE (source, path) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IF NOT EXISTS templates_source_idx ON templates (source);
CREATE INDEX IF NOT EXISTS templates_severity_idx ON templates (severity);
CREATE INDEX IF NOT EXISTS templates_tags_gin_idx ON templates USING GIN (tags);
CREATE INDEX IF NOT EXISTS templates_active_name_idx ON templates (availability, lower(name));

CREATE TABLE IF NOT EXISTS template_sync_runs (
    id          UUID PRIMARY KEY,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status      TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed')),
    ref_before  TEXT,
    ref_after   TEXT,
    added       INTEGER NOT NULL DEFAULT 0,
    removed     INTEGER NOT NULL DEFAULT 0,
    updated     INTEGER NOT NULL DEFAULT 0,
    skipped     INTEGER NOT NULL DEFAULT 0,
    error       TEXT
);

CREATE INDEX IF NOT EXISTS template_sync_runs_started_at_idx ON template_sync_runs (started_at DESC);
