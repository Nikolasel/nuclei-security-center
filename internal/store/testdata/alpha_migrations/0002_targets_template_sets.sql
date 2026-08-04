-- Phase 1: the two config resources users manage in the UI, plus a link from a
-- scan back to the config it came from.

CREATE TABLE IF NOT EXISTS targets (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    -- hosts is the scope allowlist: hostnames / IPs / CIDRs / URLs a scan may hit.
    hosts      TEXT[] NOT NULL,
    tags       TEXT[] NOT NULL DEFAULT '{}',
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Names are a human handle; keep them unique case-insensitively.
CREATE UNIQUE INDEX IF NOT EXISTS targets_name_key ON targets (lower(name));

CREATE TABLE IF NOT EXISTS template_sets (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    git_ref    TEXT,
    severities TEXT[] NOT NULL DEFAULT '{}',
    tags       TEXT[] NOT NULL DEFAULT '{}',
    paths      TEXT[] NOT NULL DEFAULT '{}',
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS template_sets_name_key ON template_sets (lower(name));

-- A scan may originate from a stored target/template set (nullable: ad-hoc scans
-- have neither). ON DELETE SET NULL so deleting config never erases scan history.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS target_id       UUID REFERENCES targets(id)       ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS template_set_id UUID REFERENCES template_sets(id) ON DELETE SET NULL;
