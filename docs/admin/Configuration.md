# Configuration

All configuration is environment-based. Required values fail fast. Go-duration values use forms
such as `30s`, `15m`, and `6h`.

An administrator can inspect the **effective** values the running backend process is using
(set vs unset, parsed booleans/durations, redacted DSNs) on **Settings → Environment
configuration**. That page is read-only: changing a variable still requires a redeploy or
restart. The tables below are the same allowlist the API uses; scanner-node variables are
documented separately because the backend never sees them.

## Backend

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND_ADDR` | `:8080` | HTTP listen address. |
| `DATABASE_URL` | required | PostgreSQL DSN. Use TLS in production. |
| `DATABASE_PASSWORD_FILE` | unset | File containing only the DB password. Re-read before each new connection so credentials can rotate without a restart. |
| `SCANNER_URL` | `http://localhost:8081` | Endpoint used to seed the first catch-all scanner node. Seed-only after first boot. |
| `SCANNER_TOKEN` | required, at least 32 characters on the scanner | Token used with SCANNER_URL to seed the default node. At least 32 characters on the scanner. |
| `SCAN_ZONES` | unset | JSON array of additional seed nodes. Seed-only; PostgreSQL is authoritative afterward. |
| `NODE_HEALTH_INTERVAL` | `30s` | Capability-poll interval. A node stays healthy for three times this interval after its last successful poll. |
| `RETENTION_SWEEP_INTERVAL` | `1h` | How often the backend applies the DB-backed scan-retention policy. |
| `TEMPLATE_SYNC_INTERVAL` | `6h` | Upstream catalog refresh cadence. Env-only; the source repository and ref are runtime settings. |
| `TEMPLATE_SYNC_REPO` | ProjectDiscovery `nuclei-templates` Git repository | Upstream catalog Git repository. Seeds the DB-backed source once at startup; afterward the admin UI (Templates → Sync) is authoritative and this variable only matters when never seeded. An explicit empty value disables upstream sync while retaining custom templates and distribution. |
| `TEMPLATE_SYNC_REF` | `latest` | Revision to mirror. Seeds the DB-backed source once at startup; afterward the admin UI is authoritative. latest is the highest stable tag; tags and SHAs are reproducible, branches advance. |
| `TEMPLATE_SYNC_DIR` | `/tmp/nsc-template-sync` | Backend clone cache. Mount persistent storage to avoid repeated full clones. Source probes reuse this clone for the configured repository (under the sync worktree lock) and probe any other candidate in a throwaway temp directory that is removed afterwards, so a dry run never invalidates or duplicates the real clone. Previews of a different repository clone it into the system temp directory (os.TempDir(), usually /tmp): on a read-only root it must be writable, and if it is a memory-backed tmpfs the clone counts against the pod's memory for the duration of the preview. |
| `TEMPLATE_DISTRIBUTE_INTERVAL` | `1h` | How often stale, idle scanner nodes receive the current full catalog bundle. Pre-dispatch top-up still runs. |
| `EXPORT_SPOOL_DIR` | `os.TempDir()` (usually `/tmp`) | Writable scratch directory for findings exports and scan-bundle imports. |

Reserve at least 512 MiB in `EXPORT_SPOOL_DIR` for four simultaneous 64 MiB exports plus up to
512 MiB for the one in-flight scan-bundle ZIP spool; SARIF uses a second bounded rule spool. On a
read-only-root deployment mount a writable `emptyDir`/volume and point this variable at it, and keep
the system temp directory (`/tmp`) writable as well: a preview of a different template repository
clones that repository into `os.TempDir()` (see the `TEMPLATE_SYNC_DIR` note above).
Generate `SCANNER_TOKEN` with `openssl rand -base64 24`.

### Upstream template source: env seeds once, the database wins

The upstream template source (repository + ref) is a **runtime setting**, not an environment
setting. On first boot after this migration the NULL `app_settings` columns are seeded once from
`TEMPLATE_SYNC_REPO` / `TEMPLATE_SYNC_REF` (including their defaults); from then on the stored
values are authoritative and the environment is never re-applied over them. An env that differs
from the stored source only logs a drift note at startup — change the source under
**Templates → Sync → Change source** (admin), which stores, validates against the fetched
repository, and queues an immediate sync. Only `https://` repositories are accepted (`http://`,
`git://`, `file://` and bare paths are refused — plaintext remotes could tamper with templates that
run against targets). SSH remotes are also refused: the go-git client would need an explicit key
and `known_hosts` setup the container does not ship, so an `ssh://` URL could never resolve as
configured; use `https://` with credentials embedded in the URL (stored, never shown). Connection
failures surface as a generic error — the raw dial error goes only to the backend log.
`TEMPLATE_SYNC_INTERVAL` (cadence) and
`TEMPLATE_SYNC_DIR` (clone cache) remain env-only. An explicit empty repository means "upstream
sync disabled" — custom templates and node distribution keep working. The effective environment
view on Settings marks both seeding variables as seed-only and shows the stored value as
effective (repository sanitized).

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
| `OIDC_ISSUER` | required unless `AUTH_DISABLED=true` | Browser-visible issuer URL. Setting it enables OIDC/BFF auth. Required unless AUTH_DISABLED is true. |
| `AUTH_DISABLED` | `false` | Explicit all-roles development mode when OIDC_ISSUER is unset. Never use in production. |
| `OIDC_DISCOVERY_URL` | `OIDC_ISSUER` | Internal metadata URL when the backend reaches the issuer at a different address. |
| `OIDC_CLIENT_ID` | required with OIDC | Confidential client ID. Required with OIDC. |
| `OIDC_CLIENT_SECRET` | required with OIDC | Confidential client secret. Required with OIDC. |
| `APP_BASE_URL` | `http://localhost:8080` | Canonical public application URL. Browser login and the SPA redirect onto this origin when Host differs. |
| `OIDC_REDIRECT_URL` | `APP_BASE_URL/api/auth/callback` | Callback registered with the IdP. |
| `POST_LOGIN_REDIRECT` | `APP_BASE_URL/` | Browser destination after login. |
| `OIDC_SCOPES` | `openid,profile,email` | Comma-separated scopes. |
| `OIDC_ROLES_CLAIM` | `groups` | ID-token claim containing groups or roles. |
| `OIDC_ADMIN_GROUP` | `admin` | Group mapped to NSC admin. |
| `OIDC_OPERATOR_GROUP` | `operator` | Group mapped to NSC operator. |
| `OIDC_VIEWER_GROUP` | `viewer` | Group mapped to NSC viewer. |
| `SESSION_TTL` | `12h` | Server-side session lifetime, between 15m and 24h. Longer values are rejected. |
| `SESSION_COOKIE_NAME` | `__Host-nsc_session` when `COOKIE_SECURE=true`; `nsc_session` otherwise | Session cookie name. Secure deployments use the Host- prefix. |
| `COOKIE_SECURE` | `true` | Secure-cookie flag. Set false only for local plaintext HTTP. |
| `AUTH_MAX_LIVE_FLOWS` | `10000` | Global active browser-flow cap across backend replicas. At the cap, new flows fail closed with 429. |
| `AUTH_LOGIN_RATE` | `1` | Per-peer login-flow token refill rate in requests per second. |
| `AUTH_LOGIN_BURST` | `5` | Per-peer login burst. |
| `AUTH_LOGIN_MAX_CLIENTS` | `4096` | Maximum in-memory peer limiters; the stalest entry is evicted at capacity. |
| `AUTH_TRUSTED_PROXY_CIDRS` | unset | Comma-separated trusted proxy CIDRs (maximum 64). Only matching direct peers may supply sanitized X-Forwarded-For client addresses. |

Accepted ranges fail closed at startup: `AUTH_MAX_LIVE_FLOWS` 1–100000, `AUTH_LOGIN_RATE` 0.000001–1000, `AUTH_LOGIN_BURST` 1–1000, and `AUTH_LOGIN_MAX_CLIENTS` 1–65536. `SESSION_TTL` also drives [session-revocation and privilege-revocation latency](Authentication.md#session-revocation-and-privilege-revocation-latency).

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
| `S3_ENDPOINT` | unset (archiving disabled) | S3-compatible endpoint as host:port, without a scheme. Unset disables archiving. |
| `S3_BUCKET` | `nuclei-raw` | Archive bucket; created at startup when absent. |
| `S3_ACCESS_KEY_ID` | unset | Static access key. Leave empty to use the ambient AWS credential chain. |
| `S3_SECRET_ACCESS_KEY` | unset | Static secret key. |
| `S3_REGION` | `us-east-1` | S3 region. Must match the store's configured region. |
| `S3_USE_SSL` | `true` | TLS for the S3 endpoint. Set false only for local plaintext HTTP. |

Compose runs unmodified [Garage](https://garagehq.deuxfleurs.fr/) (`dxflrs/garage`, AGPL-3.0)
as the local S3 endpoint. The image tag is `${GARAGE_VERSION:-v2.3.0}`: `dxflrs/garage` publishes
no `latest` tag, so the compose file keeps `v2.3.0` as the known-good default. Set `GARAGE_VERSION`
in `.env` to try a newer release or pin one tag for a test run. To change the default, bump the
compose fallback after checking [garagehq.deuxfleurs.fr](https://garagehq.deuxfleurs.fr/) or the
[Garage releases](https://git.deuxfleurs.fr/Deuxfleurs/garage/releases). Running that unmodified
image is appropriate for development and for self-hosting. Revisit the choice if NSC ever patches
Garage and ships that modified build: AGPL-3.0 would then require offering the corresponding Garage
source. The application client stays `minio-go`; it
speaks generic S3, and the same `S3_*` variables point at AWS S3 or another compatible API in
production. The Compose access key and secret are the development values in
`docker-compose.yml` (`GARAGE_DEFAULT_ACCESS_KEY` / `GARAGE_DEFAULT_SECRET_KEY`).

The backend archives byte-exact raw Nuclei output and execution logs best-effort. PostgreSQL remains
the system of record: an archive upload failure is logged but does not discard successfully ingested
findings. Downloads are proxied through the authenticated backend; NSC does not expose presigned
URLs.

## Scan email notifications

Unset `SMTP_HOST` leaves mail off. Host plus `SMTP_FROM` is enough to enable sending;
`SMTP_TO` is the fallback recipient list when a policy names none. A completed scan with
no New / Changed / Fixed delta sends nothing. Failed and orphaned scans use the same
policy flag and recipients as digests (flag off ⇒ no failure mail). Operator-cancelled
scans do not mail. Non-standard severities (including Nuclei's `unknown`) are
counted in an `unknown` bucket rather than `info`. Send failures are logged and never
change the scan's terminal state. Recipients authenticate through the normal session; mails link to
`APP_BASE_URL` scan and finding pages (no presigned URLs). `SMTP_PASSWORD_FILE` is re-read on each
send so a secret agent can rotate credentials.

| Variable | Default | Purpose |
|---|---|---|
| `SMTP_HOST` | unset (mail disabled) | SMTP server hostname. Unset disables notifications without failing startup. |
| `SMTP_PORT` | `587` | SMTP port. Must be 1-65535; invalid values disable mail. |
| `SMTP_USERNAME` | unset | SMTP AUTH username. Leave empty for unauthenticated relays. |
| `SMTP_PASSWORD` | unset | SMTP AUTH password. Ignored when SMTP_PASSWORD_FILE is set. |
| `SMTP_PASSWORD_FILE` | unset | File containing only the SMTP password. Re-read before each send. |
| `SMTP_FROM` | unset | Envelope From. Required with SMTP_HOST or mail stays disabled. |
| `SMTP_TO` | unset | Comma-separated fallback recipients when a policy lists none. Optional: host + SMTP_FROM enable sending; a policy with no recipients and no SMTP_TO skips SMTP as no_recipients. |
| `SMTP_STARTTLS` | `true` | Require STARTTLS on the submission port. Set false only for a trusted plaintext relay. |
| `SMTP_TLS` | `false` | Implicit TLS (typically port 465). When true, STARTTLS is not used. |

See [Operations](Operations.md#scan-email-notifications) for what a digest contains.

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
