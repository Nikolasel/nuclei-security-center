-- Scan policy (#87) — the central, reusable scan configuration. A policy bundles
-- EVERYTHING a scan needs: which target to scan (scope), which template set to
-- run, and Nuclei's execution knobs (rate limit / concurrency / timeout /
-- max-host-error). Every scan — ad-hoc or scheduled — is launched by selecting a
-- policy; nothing else is specified at dispatch. This is a breaking change vs.
-- the POC (alpha): the ad-hoc target/template/spec inputs and the per-schedule
-- target/template/timeout columns are replaced by a single scan_policy_id.
--
-- The scope guardrail (§6) is preserved by construction: a policy references a
-- stored target (the allowlist), so a scan can never name an out-of-scope host.

CREATE TABLE IF NOT EXISTS scan_policies (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    -- What to scan: a stored target (required — the scope) and an optional
    -- template set (NULL = all templates). Deleting the target cascades the
    -- policy away (like the old target→schedule cascade); deleting the template
    -- set just drops the policy back to "all templates".
    target_id       UUID NOT NULL REFERENCES targets(id)       ON DELETE CASCADE,
    template_set_id UUID          REFERENCES template_sets(id) ON DELETE SET NULL,
    -- How to scan: Nuclei execution knobs. NULL = the built-in default
    -- (rate 150 / concurrency 25 / timeout 600s / max-host-error Nuclei's own 30),
    -- so a policy can tune just one knob and leave the rest.
    rate_limit      INTEGER,
    concurrency     INTEGER,
    timeout_sec     INTEGER,
    max_host_error  INTEGER,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Names are a human handle; keep them unique case-insensitively (matches
-- targets/template_sets).
CREATE UNIQUE INDEX IF NOT EXISTS scan_policies_name_key ON scan_policies (lower(name));

-- A scan records which policy produced it. ON DELETE SET NULL so deleting a
-- policy never erases scan history (the scan's own target_id/template_set_id
-- columns, resolved at dispatch, stay put — findings keep working).
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_policy_id UUID REFERENCES scan_policies(id) ON DELETE SET NULL;

-- Schedules are now driven entirely by a scan policy. The old target/template/
-- timeout columns move into the policy. Existing POC schedules predate policies
-- and can't be mapped to one, so clear them before making scan_policy_id
-- NOT NULL (alpha; breaking). Deleting a policy cascades its schedules away.
DELETE FROM schedules;
ALTER TABLE schedules
    DROP COLUMN IF EXISTS target_id,
    DROP COLUMN IF EXISTS template_set_id,
    DROP COLUMN IF EXISTS timeout_sec,
    ADD COLUMN scan_policy_id UUID NOT NULL REFERENCES scan_policies(id) ON DELETE CASCADE;
