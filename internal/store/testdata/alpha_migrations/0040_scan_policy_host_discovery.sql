-- Host discovery is independent from naabu's SYN/connect port-scan mode (#133).
-- NULL deliberately preserves the existing mode-dependent behavior: SYN runs a
-- host-discovery pass and connect skips it. TRUE adds the pass for either mode;
-- FALSE skips it for either mode.
ALTER TABLE scan_policies
    ADD COLUMN IF NOT EXISTS discovery_host_discovery BOOLEAN;

COMMENT ON COLUMN scan_policies.discovery_host_discovery IS
    'Whether naabu runs a host-discovery pass before port scanning; NULL preserves the scan-type default';
