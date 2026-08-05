ALTER TABLE scans
    ADD COLUMN coverage_origin text NOT NULL DEFAULT 'node';

-- Rows without a node scan id are historical imports or pre-dispatch records.
-- Mark them untrusted before lifecycle repair starts consulting provenance.
UPDATE scans
   SET coverage_origin = 'import_untrusted'
 WHERE node_scan_id IS NULL;

ALTER TABLE scans
    ADD CONSTRAINT scans_coverage_origin_check
    CHECK (coverage_origin IN ('node', 'import_untrusted', 'import_trusted'));

COMMENT ON COLUMN scans.coverage_origin IS
    'Provenance of covered_endpoints: node, import_untrusted, or import_trusted';
