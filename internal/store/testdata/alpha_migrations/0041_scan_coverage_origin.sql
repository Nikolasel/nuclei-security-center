-- Preserve the provenance of request-trace coverage evidence (#181).
--
-- Only node-produced scans and explicitly trusted imports may use
-- covered_endpoints as lifecycle mitigation evidence. Ordinary imports retain
-- the scan and its findings but are marked untrusted by the backend.
ALTER TABLE scans
    ADD COLUMN coverage_origin TEXT NOT NULL DEFAULT 'import_untrusted';

ALTER TABLE scans
    ADD CONSTRAINT scans_coverage_origin_check
        CHECK (coverage_origin IN ('node', 'import_untrusted', 'import_trusted'));

COMMENT ON COLUMN scans.coverage_origin IS
    'Provenance of covered_endpoints: node, import_untrusted, or import_trusted';
