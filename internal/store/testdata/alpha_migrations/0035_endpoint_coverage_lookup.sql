-- Scheme-less HTTP findings still carry their protocol in Nuclei's `type`
-- field. Migration 0034 omitted HTTP/HTTPS from its protocol defaults, so repair
-- only the rows that remained structurally unkeyed. The helper mirrors 0034
-- plus those two defaults and is dropped immediately after the repair.
CREATE FUNCTION nsc_endpoint_key_0035(value TEXT, protocol TEXT)
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
            WHEN lower(coalesce(protocol, '')) = 'http' THEN '80'
            WHEN lower(coalesce(protocol, '')) = 'https' THEN '443'
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
   SET endpoint_key = nsc_endpoint_key_0035(matched_at, type)
 WHERE endpoint_key = ''
   AND lower(type) IN ('http', 'https');

DROP FUNCTION nsc_endpoint_key_0035(TEXT, TEXT);

-- Scan completion expands exact template+endpoint trace evidence once, then
-- joins it to lifecycle rows. Keep that join index-served as both the finding
-- corpus and a scan's coverage-pair set grow (#91).
CREATE INDEX finding_lifecycle_template_endpoint_idx
    ON finding_lifecycle (template_id, endpoint_key)
    WHERE endpoint_key <> '';
