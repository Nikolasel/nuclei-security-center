-- Target groups (#13): a named, static set of existing targets. A group is a
-- convenience subset of the union of all targets — it is NOT a new scope source.
-- The scope guardrail (§6) stays the union of every target's hosts; a group just
-- lets a user run/schedule against several targets at once, fanning out to one
-- scan per member target (each in-scope by construction).

CREATE TABLE IF NOT EXISTS target_groups (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Static membership: a group holds a set of existing target rows. Both FKs
-- cascade, so deleting a target drops it from every group and deleting a group
-- drops its membership rows (never the targets themselves).
CREATE TABLE IF NOT EXISTS target_group_members (
    group_id  UUID NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id)       ON DELETE CASCADE,
    PRIMARY KEY (group_id, target_id)
);
CREATE INDEX IF NOT EXISTS target_group_members_target_idx ON target_group_members (target_id);

-- Schedules may now target a group instead of a single target. Exactly one of
-- target_id / target_group_id is set (existing rows keep their target_id).
ALTER TABLE schedules ALTER COLUMN target_id DROP NOT NULL;
ALTER TABLE schedules ADD COLUMN IF NOT EXISTS target_group_id UUID REFERENCES target_groups(id) ON DELETE CASCADE;

-- ADD CONSTRAINT has no IF NOT EXISTS; guard so a re-applied migration is a no-op.
DO $$ BEGIN
    ALTER TABLE schedules ADD CONSTRAINT schedules_one_target
        CHECK ((target_id IS NOT NULL) <> (target_group_id IS NOT NULL));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
