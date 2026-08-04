-- Per-node mTLS for the backend→scanner path (#26). Each node can carry its own
-- server CA (to pin the node's server certificate) plus the client certificate +
-- key the backend presents to that node. The key is a secret, handled write-only
-- at the API the same way the bearer token is; the CA and client cert are public
-- and returned on reads. Empty (the default) ⇒ plain HTTP/token as before.
ALTER TABLE scanner_nodes
    ADD COLUMN tls_server_ca   TEXT NOT NULL DEFAULT '',
    ADD COLUMN tls_client_cert TEXT NOT NULL DEFAULT '',
    ADD COLUMN tls_client_key  TEXT NOT NULL DEFAULT '';
