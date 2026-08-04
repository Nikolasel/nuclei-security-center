-- Naabu port-discovery pre-pass (#86). A scan policy can drive an optional naabu
-- port scan on the scanner node BEFORE Nuclei, so Nuclei only probes live
-- host:port pairs instead of every address in a CIDR-scoped target.
--
-- Discovery is ON by default (discovery_enabled DEFAULT TRUE): it is the win for
-- the large-range targets that motivated the feature, and existing policies
-- inherit it. It fails closed on the node — a naabu error aborts the scan — so an
-- operator turns it OFF here per policy when discovery is unavailable or unwanted.
ALTER TABLE scan_policies
    ADD COLUMN IF NOT EXISTS discovery_enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    -- naabu -port spec (e.g. '80,443,8000-9000', multiple ranges allowed).
    -- NULL = naabu's top-1000 ports (the nmap top-1000 set).
    ADD COLUMN IF NOT EXISTS discovery_ports       TEXT,
    -- Discovery's OWN time budget in seconds, separate from timeout_sec (which
    -- stays the Nuclei budget). NULL = the node's built-in discovery default.
    ADD COLUMN IF NOT EXISTS discovery_timeout_sec INTEGER;
