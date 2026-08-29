# Configuration

All configuration is environment-based. Required values fail fast. Go-duration values use forms
such as `30s`, `15m`, and `6h`.

## Backend

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND_ADDR` | `:8080` | HTTP listen address. |
| `DATABASE_URL` | required | PostgreSQL DSN. Use TLS in production. |
| `DATABASE_PASSWORD_FILE` | unset | File containing only the DB password. It is re-read before each new connection, allowing an external secret agent to rotate credentials without restarting NSC. |
| `SCANNER_URL` | `http://localhost:8081` | Endpoint used to seed the first catch-all scanner node. Seed-only after first boot. |
| `SCANNER_TOKEN` | required, at least 32 characters on the scanner | Token used with `SCANNER_URL` to seed the default node. Generate with `openssl rand -base64 24`. |
| `SCAN_ZONES` | unset | JSON array of additional seed nodes with `name`, `url`, `token`, `cidrs`, optional `max_concurrent_scans`, and optional per-node TLS fields. Seed-only; PostgreSQL is authoritative afterward. |
| `NODE_HEALTH_INTERVAL` | `30s` | Capability-poll interval. A node stays healthy for three times this interval after its last successful poll. |
| `RETENTION_SWEEP_INTERVAL` | `1h` | How often the backend applies the DB-backed scan-retention policy. |
| `TEMPLATE_SYNC_INTERVAL` | `6h` | Upstream catalog refresh cadence. |
| `TEMPLATE_SYNC_REPO` | ProjectDiscovery `nuclei-templates` Git repository | Upstream catalog. Set the variable to an explicit empty value to disable upstream sync while retaining custom templates and distribution. |
| `TEMPLATE_SYNC_REF` | `latest` | Revision to mirror. `latest` resolves to the highest stable semantic-version tag; tags and commit SHAs are reproducible, while branch names advance. |
| `TEMPLATE_SYNC_DIR` | `/tmp/nsc-template-sync` | Backend clone cache. Mount persistent storage to avoid repeated full clones. |
| `TEMPLATE_DISTRIBUTE_INTERVAL` | `1h` | How often stale, idle scanner nodes receive the current full catalog bundle. Pre-dispatch top-up still runs. |
| `EXPORT_SPOOL_DIR` | `os.TempDir()` (usually `/tmp`) | Writable backend-local scratch directory for findings exports and scan-bundle imports. Reserve at least 512 MiB for four simultaneous 64 MiB exports plus up to 512 MiB for the one in-flight scan-bundle ZIP spool; SARIF uses a second bounded rule spool. On a read-only-root deployment mount a writable `emptyDir`/volume and point this variable at it. |

Scanner nodes likewise need writable scratch: the image's HOME directory (`/home/scanner`) for nuclei/naabu/uncover config cache (`$HOME/.config`, `$HOME/nuclei-templates`) and `SCANNER_WORK_DIR` (defaults to a private `0700` dir under `os.TempDir()`/`/tmp`) for per-scan work dirs. On a `read_only: true` deployment mount writable `emptyDir`/tmpfs volumes at both paths, as with `EXPORT_SPOOL_DIR`/`TEMPLATE_SYNC_DIR` for the backend.

`SCAN_ZONES` uses this JSON shape (the three PEM-valued TLS keys are optional):

```sh
export SCAN_ZONES='[{"name":"dmz","url":"https://scanner-dmz:8081","token":"replace-with-a-strong-token","cidrs":["10.20.0.0/16"],"max_concurrent_scans":4,"tls_server_ca":"<PEM CA>","tls_client_cert":"<PEM client certificate>","tls_client_key":"<PEM client key>"}]'
```

Use escaped `\n` characters inside JSON strings when embedding multiline PEM values. Seed entries
are insert-only by node name; PostgreSQL and subsequent API/UI edits are authoritative.

## Authentication and sessions

| Variable | Default | Purpose |
|---|---|---|
| `OIDC_ISSUER` | required unless `AUTH_DISABLED=true` | Browser-visible issuer URL. Setting it enables OIDC/BFF auth. |
| `AUTH_DISABLED` | `false` | Explicit all-roles development mode when `OIDC_ISSUER` is unset. Never use in production. |
| `OIDC_DISCOVERY_URL` | `OIDC_ISSUER` | Internal metadata URL when the backend reaches the issuer at a different address. |
| `OIDC_CLIENT_ID` | required with OIDC | Confidential client ID. |
| `OIDC_CLIENT_SECRET` | required with OIDC | Confidential client secret. |
| `APP_BASE_URL` | `http://localhost:8080` | Public application URL. |
| `OIDC_REDIRECT_URL` | `APP_BASE_URL/api/auth/callback` | Callback registered with the IdP. |
| `POST_LOGIN_REDIRECT` | `APP_BASE_URL/` | Browser destination after login. |
| `OIDC_SCOPES` | `openid,profile,email` | Comma-separated scopes. |
| `OIDC_ROLES_CLAIM` | `groups` | ID-token claim containing groups/roles. |
| `OIDC_ADMIN_GROUP` | `admin` | Group mapped to NSC admin. |
| `OIDC_OPERATOR_GROUP` | `operator` | Group mapped to NSC operator. |
| `OIDC_VIEWER_GROUP` | `viewer` | Group mapped to NSC viewer. |
| `SESSION_TTL` | `12h` | Server-side session lifetime. Must be between `15m` and `24h`; longer values are rejected. The maximum bounds the worst-case privilege-revocation latency when a role is removed at the IdP — see [session revocation](Authentication.md#session-revocation-and-privilege-revocation-latency). |
| `SESSION_COOKIE_NAME` | `__Host-nsc_session` when `COOKIE_SECURE=true`; `nsc_session` otherwise | Session cookie name. Secure deployments enforce the `__Host-` prefix. |
| `COOKIE_SECURE` | `true` | Secure-cookie flag. Set `false` only for local plaintext HTTP. |
| `AUTH_MAX_LIVE_FLOWS` | `10000` | Global active browser-flow cap across backend replicas (`1`–`100000`). At the cap, new flows fail closed with `429`. |
| `AUTH_LOGIN_RATE` | `1` | Per-peer login-flow token refill rate in requests/second (`0.000001`–`1000`). |
| `AUTH_LOGIN_BURST` | `5` | Per-peer login burst (`1`–`1000`). |
| `AUTH_LOGIN_MAX_CLIENTS` | `4096` | Maximum in-memory peer limiters (`1`–`65536`); the stalest entry is evicted at capacity. |
| `AUTH_TRUSTED_PROXY_CIDRS` | unset | Comma-separated trusted proxy CIDRs (maximum 64). Only matching direct peers may supply sanitized `X-Forwarded-For` client addresses. |

When `COOKIE_SECURE=true`, the session cookie is host-locked: it uses the `__Host-` prefix, `Path=/`,
`Secure`, and no `Domain` attribute. This prevents a sibling subdomain from setting a competing
session cookie for the backend. Session identifiers created on the current schema are stored only as
SHA-256 hashes. Existing session rows are not converted; their old plaintext identifiers cannot
authenticate because presented cookie values are hashed before lookup, and the expiry sweeper removes
the rows. Set `COOKIE_SECURE=false` only for local plaintext HTTP, where browsers reject `__Host-`
cookies.

The public login entrypoint is protected by two admission layers. The backend applies a per-peer
token-bucket limiter. By default it keys from the TCP peer address and ignores forwarded headers.
If `AUTH_TRUSTED_PROXY_CIDRS` is configured and the direct peer matches one of those networks, it
walks the `X-Forwarded-For` chain from the nearest hop outward and uses the first untrusted address;
the proxy must strip or overwrite client-supplied forwarding headers before this boundary. Missing
or malformed forwarding data falls back to the direct peer. Its in-memory table is bounded by lazy
least-recently-seen eviction when full; the request path does not scan the entire table to reap idle
entries. PostgreSQL also caps live
authorization flows across backend replicas, using a non-blocking advisory-lock probe so competing
login attempts do not queue pooled connections behind one another. The live-flow query ignores
expired rows, while the background sweeper owns their physical deletion. A full global cap is an
intentional fail-closed backstop: new flows receive `429` until capacity is available again.
After three short non-blocking lock attempts, rare remaining admission contention returns `503` with
`Retry-After: 1`; an interactive browser should retry the login navigation.

If a TLS-terminating ingress proxies all requests from one address, the application limiter sees
that ingress as one shared peer rather than providing per-user isolation; in that topology the
ingress/WAF must provide the per-client rate limit. Keep an ingress/WAF rate limit in front of
`/api/auth/login` as an additional distributed control; the application limiter is defense in
depth and does not infer a trusted proxy configuration. The advisory-lock namespace is fixed in
code and is not an environment setting, preventing accidental collisions with other database
lock domains.

OIDC setup, browser mutation protection, service accounts, mTLS, and session revocation are in
[Authentication](Authentication.md).

## Object storage

| Variable | Default | Purpose |
|---|---|---|
| `S3_ENDPOINT` | unset (archiving disabled) | S3-compatible endpoint as `host:port`, without a scheme. |
| `S3_BUCKET` | `nuclei-raw` | Archive bucket; created at startup when absent. |
| `S3_ACCESS_KEY_ID` | unset | Static access key. Leave empty to use the ambient AWS credential chain. |
| `S3_SECRET_ACCESS_KEY` | unset | Static secret key. |
| `S3_REGION` | `us-east-1` | S3 region. |
| `S3_USE_SSL` | `true` | TLS for the S3 endpoint. Set `false` only for local plaintext HTTP (e.g. MinIO in `docker compose`). |

The backend archives byte-exact raw Nuclei output and execution logs best-effort. PostgreSQL remains
the system of record: an archive upload failure is logged but does not discard successfully ingested
findings. Downloads are proxied through the authenticated backend; NSC does not expose presigned
URLs.

## Scanner

| Variable | Default | Purpose |
|---|---|---|
| `SCANNER_ADDR` | `:8081` | Node listen address. |
| `SCANNER_TOKEN` | required, minimum 32 characters | Bearer token accepted from the backend. Use a distinct secret per node where possible. |
| `NUCLEI_PATH` | `nuclei` | Nuclei executable. The image already supplies the pinned binary. |
| `NAABU_PATH` | `naabu` | Naabu executable used by discovery-enabled policies. |
| `NAABU_SCAN_TYPE` | `syn` | Node default (`syn` or `connect`) when a policy does not choose. SYN needs raw sockets and libpcap; connect is the unprivileged fallback. |
| `SCANNER_WORK_DIR` | private `0700` temporary directory (under `os.TempDir()`/`/tmp` when unset) | Per-scan work root. If set, mount a private node-local volume. On a `read_only: true` deployment mount a writable `emptyDir`/tmpfs at `/tmp` (or set this to a writable mount) and at the scanner HOME directory (`/home/scanner`) so nuclei can create `$HOME/.config`; see the note above for `EXPORT_SPOOL_DIR`/`TEMPLATE_SYNC_DIR`. |
| `SCANNER_TLS_CERT` | unset | PEM server certificate. Must be paired with `SCANNER_TLS_KEY`. |
| `SCANNER_TLS_KEY` | unset | PEM server private key. |
| `SCANNER_CLIENT_CA` | unset | CA bundle used to require and verify backend client certificates (mTLS). |
| `SCANNER_MAX_CONCURRENT_SCANS` | `20` | Standalone-node fallback admission limit (`1`–`100`) used only when a direct node caller omits the backend registry value. Normal backend dispatch sends the per-node value from PostgreSQL. |
