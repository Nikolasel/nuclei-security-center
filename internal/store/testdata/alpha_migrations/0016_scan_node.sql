-- Record which registered scanner node ran (or will run) a scan (#107). Dispatch
-- selects the node by CIDR match at submit time but previously forgot it, so an
-- operator couldn't tell which node handled a given scan. node_id references the
-- scanner_nodes registry (#22); ON DELETE SET NULL so deleting a node doesn't
-- orphan scan history (the scan then reads as "—", like a deleted target). The
-- API exposes the resolved node_name, never the node's token/endpoint.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS node_id UUID
    REFERENCES scanner_nodes(id) ON DELETE SET NULL;
