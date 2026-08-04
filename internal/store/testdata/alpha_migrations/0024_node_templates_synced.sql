-- Track when the backend last pushed the full template catalog to each scanner
-- node (#85). Drives the distributor's staleness check together with the node's
-- reported bundle digest. NULL = never synced (a fresh or wiped node).
ALTER TABLE scanner_nodes ADD COLUMN IF NOT EXISTS templates_synced_at TIMESTAMPTZ;
