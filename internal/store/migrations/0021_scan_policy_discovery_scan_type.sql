-- Per-policy naabu scan mode for the discovery pre-pass (#86). NULL = fall back to
-- the node's NAABU_SCAN_TYPE default. 'syn' needs the node's CAP_NET_RAW + libpcap;
-- 'connect' is the unprivileged fallback. Constrained so only known modes persist.
ALTER TABLE scan_policies
    ADD COLUMN discovery_scan_type TEXT
        CHECK (discovery_scan_type IN ('syn', 'connect'));
