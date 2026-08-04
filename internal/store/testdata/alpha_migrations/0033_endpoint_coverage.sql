-- Endpoint-level lifecycle coverage (#91).
--
-- Nuclei's request trace supplies positive evidence for hosts that answered at
-- least one request. NULL covered_hosts means telemetry is unavailable (legacy
-- scan / parser failure); an empty array means the trace was read successfully
-- and no host was reached. finding_lifecycle.endpoint_host is the normalized
-- host component of matched_at used to join that evidence.
ALTER TABLE scans
    ADD COLUMN covered_hosts TEXT[];

ALTER TABLE finding_lifecycle
    ADD COLUMN endpoint_host TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN scans.covered_hosts IS
    'Hosts with at least one successful Nuclei trace request; NULL means coverage unknown';
COMMENT ON COLUMN finding_lifecycle.endpoint_host IS
    'Normalized host component of matched_at used for endpoint-level scan coverage';

-- Backfill existing lifecycle rows. New ingestion uses net/url + net/netip in
-- types.HostKey; this temporary function provides the equivalent migration path
-- for the URL, host:port, bracketed IPv6, and raw IP forms Nuclei emits.
CREATE FUNCTION nsc_endpoint_host_0033(value TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    authority TEXT;
    candidate TEXT;
BEGIN
    authority := btrim(coalesce(value, ''));
    authority := regexp_replace(authority, '^[A-Za-z][A-Za-z0-9+.-]*://', '');
    authority := regexp_replace(authority, '^.*@', '');
    authority := regexp_replace(authority, '[/\?#].*$', '');

    IF authority ~ '^\[[^]]+\]' THEN
        candidate := substring(authority FROM '^\[([^]]+)\]');
    ELSIF authority ~ '^[^:]+:[0-9]+$' THEN
        candidate := regexp_replace(authority, ':[0-9]+$', '');
    ELSE
        candidate := trim(both '[]' FROM authority);
    END IF;

    candidate := lower(rtrim(candidate, '.'));
    BEGIN
        RETURN host(candidate::inet);
    EXCEPTION WHEN invalid_text_representation THEN
        RETURN candidate;
    END;
END
$$;

UPDATE finding_lifecycle
   SET endpoint_host = nsc_endpoint_host_0033(matched_at);

DROP FUNCTION nsc_endpoint_host_0033(TEXT);

-- No historical scan has request-trace telemetry. Retain only exact positive
-- evidence and clear mitigation cycles that target/template-level inference
-- could not substantiate at host granularity. The next traced scan can advance
-- these pointers normally.
UPDATE finding_lifecycle
   SET last_covering_scan = last_seen_scan,
       times_mitigated = 0;
