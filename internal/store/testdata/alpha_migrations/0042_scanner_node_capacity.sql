-- Scanner-node admission is node-local: different zones can have different
-- CPU, memory, raw-socket, and egress budgets. The backend registry is the
-- authoritative source; the backend sends this value with each dispatch.
ALTER TABLE scanner_nodes
    ADD COLUMN max_concurrent_scans integer DEFAULT 20 NOT NULL;

ALTER TABLE scanner_nodes
    ADD CONSTRAINT scanner_nodes_max_concurrent_scans_check
    CHECK (max_concurrent_scans > 0 AND max_concurrent_scans <= 100);
