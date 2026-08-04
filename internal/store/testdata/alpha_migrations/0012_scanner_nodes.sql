-- Scanner node registry (#22). Replaces the config-only list of scanner nodes
-- (SCANNER_URL + SCAN_ZONES) with a DB-backed registry the admin manages via the
-- API/UI. Config still seeds this table on first boot, but the DB is the system
-- of record thereafter: an admin edit is never re-clobbered by config.
--
-- A "node" collapses the old scan-zone and node into one entity (they were
-- already 1:1 in SCAN_ZONES): a reachable scanner endpoint + its bearer token,
-- plus the CIDR ranges it serves. A node with no CIDRs is a catch-all, used for
-- hostname targets (zone matching is DNS-free) and IPs matching no other node.
--
-- Invariant preserved: the node still initiates nothing toward the backend. This
-- registry is written by the admin (or the config seed), not by the nodes.
CREATE TABLE IF NOT EXISTS scanner_nodes (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,                     -- stable identity / config key
    endpoint   TEXT NOT NULL,                     -- base URL the backend calls
    token      TEXT NOT NULL,                     -- bearer token to reach the node
    cidrs      TEXT[] NOT NULL DEFAULT '{}',      -- served ranges; empty = catch-all
    tags       TEXT[] NOT NULL DEFAULT '{}',
    created_by TEXT,                              -- OIDC subject / service account
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Name is the identity key: config seeding inserts only when the name is absent,
-- so a UI/API edit to a seeded node survives restart. Unique so that rule is
-- unambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS scanner_nodes_name_key ON scanner_nodes (name);
