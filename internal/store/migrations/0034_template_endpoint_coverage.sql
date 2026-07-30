-- Complete #91 with template+endpoint coverage.
--
-- Migration 0033 recorded host-only evidence during development. That cannot
-- distinguish services on different ports or prove that a template ran before
-- max-host-error abandoned the host. Preserve 0033's immutable checksum, add the
-- precise representation here, then remove the superseded columns.
ALTER TABLE scans
    ADD COLUMN covered_endpoints JSONB,
    ADD COLUMN coverage_warning TEXT,
    ADD CONSTRAINT scans_covered_endpoints_array
        CHECK (covered_endpoints IS NULL OR jsonb_typeof(covered_endpoints) = 'array');

ALTER TABLE finding_lifecycle
    ADD COLUMN endpoint_key TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN scans.covered_endpoints IS
    'Successful Nuclei request evidence as [{template_id, endpoint(host:port)}]; NULL means unknown';
COMMENT ON COLUMN scans.coverage_warning IS
    'Fail-closed request-trace diagnostic surfaced on scan detail';
COMMENT ON COLUMN finding_lifecycle.endpoint_key IS
    'Canonical host:port derived from matched_at for template+endpoint coverage';

CREATE FUNCTION nsc_endpoint_key_0034(value TEXT, protocol TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    raw_value TEXT := btrim(coalesce(value, ''));
    scheme TEXT := '';
    authority TEXT;
    candidate TEXT;
    port_value TEXT := '';
BEGIN
    IF raw_value ~ '^[A-Za-z][A-Za-z0-9+.-]*://' THEN
        scheme := lower(substring(raw_value FROM '^([A-Za-z][A-Za-z0-9+.-]*)://'));
    END IF;
    authority := regexp_replace(raw_value, '^[A-Za-z][A-Za-z0-9+.-]*://', '');
    authority := regexp_replace(authority, '^.*@', '');
    authority := regexp_replace(authority, '[/\?#].*$', '');

    IF authority ~ '^\[[^]]+\]:[0-9]+$' THEN
        candidate := substring(authority FROM '^\[([^]]+)\]');
        port_value := substring(authority FROM '\]:([0-9]+)$');
    ELSIF authority ~ '^\[[^]]+\]$' THEN
        candidate := substring(authority FROM '^\[([^]]+)\]');
    ELSIF authority ~ '^[^:]+:[0-9]+$' THEN
        candidate := substring(authority FROM '^([^:]+):');
        port_value := substring(authority FROM ':([0-9]+)$');
    ELSIF authority !~ ':' THEN
        candidate := authority;
    ELSE
        candidate := trim(both '[]' FROM authority);
    END IF;

    IF port_value = '' THEN
        port_value := CASE
            WHEN scheme IN ('http', 'ws') THEN '80'
            WHEN scheme IN ('https', 'wss') THEN '443'
            WHEN lower(coalesce(protocol, '')) IN ('ssl', 'tls') THEN '443'
            WHEN lower(coalesce(protocol, '')) = 'dns' THEN '53'
            WHEN lower(coalesce(protocol, '')) = 'whois' THEN '43'
            ELSE ''
        END;
    END IF;
    IF candidate IS NULL OR candidate = '' OR port_value !~ '^[0-9]+$'
       OR length(port_value) > 5
       OR port_value::integer < 1 OR port_value::integer > 65535 THEN
        RETURN '';
    END IF;

    candidate := lower(rtrim(candidate, '.'));
    BEGIN
        candidate := host(candidate::inet);
    EXCEPTION WHEN invalid_text_representation THEN
        NULL;
    END;
    IF candidate ~ ':' THEN
        RETURN '[' || candidate || ']:' || port_value::integer::text;
    END IF;
    RETURN candidate || ':' || port_value::integer::text;
END
$$;

UPDATE finding_lifecycle
   SET endpoint_key = nsc_endpoint_key_0034(matched_at, type);

DROP FUNCTION nsc_endpoint_key_0034(TEXT, TEXT);

ALTER TABLE scans DROP COLUMN covered_hosts;
ALTER TABLE finding_lifecycle DROP COLUMN endpoint_host;
