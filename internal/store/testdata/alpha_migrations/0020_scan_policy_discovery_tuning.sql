-- naabu tuning knobs on the scan policy (#86). These let an operator trade
-- discovery completeness for speed on their particular range — the connect/SYN
-- defaults are conservative (per-probe timeout 1s, 3 retries) which is slow on
-- large ranges. Each NULL = naabu's own default, so a policy can tune just one.
-- Distinct from discovery_timeout_sec (the overall discovery budget): these are
-- naabu's per-probe -rate / -timeout / -retries.
ALTER TABLE scan_policies
    ADD COLUMN IF NOT EXISTS discovery_rate             INTEGER, -- naabu -rate (packets/sec)
    ADD COLUMN IF NOT EXISTS discovery_probe_timeout_ms INTEGER, -- naabu -timeout (ms per probe)
    ADD COLUMN IF NOT EXISTS discovery_retries          INTEGER; -- naabu -retries
