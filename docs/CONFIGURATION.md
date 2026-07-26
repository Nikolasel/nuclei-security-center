# Configuration

All configuration is via environment variables; required variables fail fast on startup. The
compose stack sets sane defaults for local use — this reference is for tuning and cloud
deployment.

## Environment variables

| Variable | Service | Default | Purpose |
|---|---|---|---|
| `BACKEND_ADDR` | backend | `:8080` | listen address |
| `DATABASE_URL` | backend | – (required) | Postgres DSN |
| `DATABASE_PASSWORD_FILE` | backend | – (unset ⇒ use the DSN's password) | path to a file holding **only** the DB password; re-read on every new connection so a rotated credential is picked up without restarting. See [Rotating database credentials](#rotating-database-credentials) |
| `SCANNER_URL` | backend | `http://localhost:8081` | seeds the **default** catch-all scanner node on first boot; see [Scanner node registry](#scanner-node-registry) |
| `SCAN_ZONES` | backend | – (unset ⇒ only the default node) | JSON array of CIDR-mapped scanner nodes; **seeds** the registry on first boot only (the DB is the system of record thereafter) |
| `SCANNER_TOKEN` | both | – (required, **min 32 chars**) | bearer token for backend → node calls; the node refuses to start below the floor. Mint from a CSPRNG, e.g. `openssl rand -base64 24` |
| `NODE_HEALTH_INTERVAL` | backend | `30s` | how often the backend polls each node's `/v1/capabilities` for liveness (Go duration); a node stays healthy for 3× this after its last successful poll. See [Scanner node registry](#scanner-node-registry) |
| `TEMPLATE_SYNC_INTERVAL` | backend | `6h` | cadence for the backend-owned upstream template catalog refresh (Go duration) |
| `TEMPLATE_SYNC_REPO` | backend | `https://github.com/projectdiscovery/nuclei-templates.git` | Git repository mirrored into the local template catalog. **Set empty to disable sync entirely** (mirrors the `S3_ENDPOINT`/`OIDC_ISSUER` unset-⇒-off pattern) — useful in a slim dev stack where a ~1 GB clone isn't wanted |
| `TEMPLATE_SYNC_REF` | backend | `latest` | upstream revision to mirror; `latest` selects the highest stable semantic-version Git tag. **Only tags and commit SHAs are pinned reliably**; a branch name (e.g. `main`) tracks `origin/<branch>` and advances each fetch |
| `TEMPLATE_SYNC_DIR` | backend | `/tmp/nsc-template-sync` | backend-local clone cache; PostgreSQL remains authoritative after each successful sync. Point at a persisted volume (compose does) so restarts fetch deltas instead of re-cloning |
| `TEMPLATE_DISTRIBUTE_INTERVAL` | backend | `1h` | cadence for pushing the full template catalog to scanner nodes (#85, Go duration). Each pass pushes only to nodes that are **stale** (reported bundle digest ≠ current catalog digest) **and idle** (no running scan). Distribution remains enabled when upstream sync is off so custom-only catalogs and pre-dispatch top-ups work |
| `SCANNER_ADDR` | scanner | `:8081` | listen address |
| `SCANNER_TLS_CERT` / `SCANNER_TLS_KEY` | scanner | – (unset ⇒ plain HTTP) | node server certificate; setting both makes the node serve HTTPS. See [Service auth: TLS & mTLS](#service-auth-tls--mtls) |
| `SCANNER_CLIENT_CA` | scanner | – | PEM CA bundle; when set the node **requires + verifies** a client cert (mTLS) |
| `NUCLEI_PATH` | scanner | `nuclei` | path to the nuclei binary |
| `NAABU_PATH` | scanner | `naabu` | path to the naabu binary, used for the optional port-discovery pre-pass (#86); only invoked when a scan policy enables discovery |
| `NAABU_SCAN_TYPE` | scanner | `syn` | Node **default** naabu discovery mode when a scan policy leaves `discovery_scan_type` unset: `syn` (SYN scan + host discovery — fast, prunes dead hosts; needs `CAP_NET_RAW`, in Docker's default caps, + libpcap, bundled in the image) or `connect` (unprivileged TCP connect scan, no host discovery — for deployments that drop `NET_RAW`). A policy that sets `discovery_scan_type` overrides this per scan; requesting `syn` on a node without raw sockets fails the scan closed. |
| `SCANNER_WORK_DIR` | scanner | – (unset ⇒ a private `0700` temp dir) | per-scan working dirs; leave unset for an auto-created process-exclusive dir, or point at a mounted private volume |
| `OIDC_ISSUER` | backend | – (required unless `AUTH_DISABLED=true`) | OIDC issuer URL; setting it enables auth |
| `AUTH_DISABLED` | backend | `false` | explicit opt-out to run **without** auth (dev only); required when `OIDC_ISSUER` is unset, else the backend refuses to start |
| `OIDC_DISCOVERY_URL` | backend | = `OIDC_ISSUER` | internal metadata URL when it differs from the browser-facing issuer (Docker) |
| `OIDC_CLIENT_ID` | backend | – (required if issuer set) | confidential client id |
| `OIDC_CLIENT_SECRET` | backend | – (required if issuer set) | confidential client secret |
| `APP_BASE_URL` | backend | `http://localhost:8080` | base URL for the redirect + post-login defaults |
| `OIDC_REDIRECT_URL` | backend | `APP_BASE_URL`+`/api/auth/callback` | callback URL registered with the IdP |
| `POST_LOGIN_REDIRECT` | backend | `APP_BASE_URL`+`/` | where the browser lands after login |
| `OIDC_SCOPES` | backend | `openid,profile,email` | requested scopes |
| `OIDC_ROLES_CLAIM` | backend | `groups` | ID-token claim holding the user's groups/roles |
| `OIDC_ADMIN_GROUP` / `OIDC_OPERATOR_GROUP` / `OIDC_VIEWER_GROUP` | backend | `admin` / `operator` / `viewer` | group value → role mapping |
| `SESSION_TTL` | backend | `12h` | session lifetime (Go duration) |
| `SESSION_COOKIE_NAME` | backend | `nsc_session` | session cookie name |
| `COOKIE_SECURE` | backend | `true` | session cookie `Secure` flag; set `COOKIE_SECURE=false` **only** for local plaintext-HTTP dev |
| `S3_ENDPOINT` | backend | – (unset ⇒ archiving **disabled**) | S3/MinIO endpoint `host:port` (no scheme); setting it enables raw-output archiving |
| `S3_BUCKET` | backend | `nuclei-raw` | bucket for archived raw output (created on startup if absent) |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | backend | – (empty ⇒ ambient credentials) | S3 static credentials; leave `S3_ACCESS_KEY_ID` empty to use the instance's ambient credential chain (env / shared file / EC2·ECS·EKS IAM role) instead |
| `S3_REGION` | backend | `us-east-1` | S3 region |
| `S3_USE_SSL` | backend | `false` | use TLS to the S3 endpoint |

## Authentication (OIDC/BFF)

The backend is a confidential OIDC client (the [BFF pattern](ARCHITECTURE.md#6-security-right-sized--not-the-enterprise-maximum)):
it runs the login flow server-side and hands the browser only an **httpOnly session cookie** —
no tokens ever reach JavaScript. **Roles come from the IdP**: a `groups` claim is mapped to
`admin` / `operator` / `viewer`. Authorization per endpoint — reads need `viewer`, running scans
and config writes need `operator`, deletes need `admin`.

The compose stack wires a **Keycloak** IdP seeded with realm `nsc`, a `nuclei-backend` client,
the three groups, and one demo user each (username = password):

| User | Password | Role |
|---|---|---|
| `admin` | `admin` | admin |
| `operator` | `operator` | operator |
| `viewer` | `viewer` | viewer |

Open `http://localhost:8080` and the SPA redirects you to Keycloak; after login it drops you
back into the app with a session cookie. The raw endpoints: `GET /api/auth/login` starts the
flow, `GET /api/auth/me` returns your identity + roles, `POST /api/auth/logout` ends the session.
Keycloak's own admin console is at `http://localhost:8082` (`admin`/`admin`).

Because protected endpoints authenticate via the **session cookie**, interactive callers drive
the API from the browser or a cookie jar populated by a real login. **Headless automation**
(cron/CI) instead uses a **service-account token** presented as `Authorization: Bearer <token>` —
an NSC-local, role-scoped, revocable credential minted by an admin, with no IdP involvement. See
[API → Service accounts](API.md#service-accounts).

> **Pure-API smoke testing without auth:** leave `OIDC_ISSUER` unset **and** set
> `AUTH_DISABLED=true` to run the backend in **auth-disabled dev mode** — every request acts as
> an all-roles dev user, so the `curl` examples in the [API reference](API.md) work directly. The
> backend logs a loud warning in this mode. Without the explicit `AUTH_DISABLED=true`, a missing
> `OIDC_ISSUER` is a fatal startup error (auth fails closed).

To point at a real IdP (Cognito, Entra, Keycloak, …), set `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET`, and `APP_BASE_URL`, register the `OIDC_REDIRECT_URL` with the provider, and
map its group claim to the three roles via `OIDC_ROLES_CLAIM` + `OIDC_*_GROUP`.

## Object storage

Raw scan output is archived to an S3-compatible bucket (see
[API → Raw scan-output archive](API.md#raw-scan-output-archive) for behavior). Enable it by
setting `S3_ENDPOINT`; leave it unset to disable archiving (the default in dev). The bucket named
by `S3_BUCKET` is created on startup if it doesn't exist. In the cloud, point these at the managed
object store — S3, GCS (S3 API), or Azure Blob:

| Environment | Object store | `S3_ENDPOINT` |
|---|---|---|
| Local / compose | MinIO | `minio:9000` |
| AWS | S3 | `s3.<region>.amazonaws.com` |
| GCP | GCS (S3-compat) | `storage.googleapis.com` |
| Azure | Blob | via an S3 gateway or an `ObjectStore` swap (`gocloud.dev/blob`) |

**Credentials.** Provide `S3_ACCESS_KEY_ID` + `S3_SECRET_ACCESS_KEY` for static keys (MinIO
locally, GCS, or any store that only takes keys). **Leave `S3_ACCESS_KEY_ID` empty** to use the
instance's *ambient* credential chain instead — environment variables, the shared AWS credentials
file, then the EC2/ECS/EKS instance-metadata IAM role. On AWS this means the backend archives raw
output using the IAM role already attached to its compute, with **no long-lived IAM user or static
keys** to mint, store in Terraform state, or rotate. Static keys win whenever `S3_ACCESS_KEY_ID`
is set, so local dev and keyed stores are unaffected.

## Rotating database credentials

The backend reads `DATABASE_URL` once at startup. Managed databases that **auto-rotate** the
password (AWS RDS-managed master password — rotated every 7 days by default; Cloud SQL + Secret
Manager; Azure Key Vault; Vault dynamic secrets) break a long-running process once the password
changes: existing pooled connections survive, but every new connection fails to authenticate
until the process restarts with a fresh DSN.

To tolerate this, keep the password **out of `DATABASE_URL`** and point `DATABASE_PASSWORD_FILE`
at a file that holds only the password:

- `DATABASE_URL` supplies host / user / database (no password, or a placeholder).
- `DATABASE_PASSWORD_FILE` is re-read **on every new connection** (via the pool's `BeforeConnect`
  hook), so a rotated password is applied to fresh connections without a restart.

This is deployment-agnostic: it works with anything that can render the current secret to a file
and keep it fresh — a Secrets Manager/Key Vault agent sidecar, a Vault agent template, a
Kubernetes projected secret, or the CSI Secrets Store driver. The app stays cloud-portable; the
secret-store specifics live at the deployment edge. A single trailing newline is trimmed; interior
and leading whitespace is preserved.

If `DATABASE_PASSWORD_FILE` is unset, the password in `DATABASE_URL` is used as before.

## Scanner node registry

Scanner nodes live in a **DB-backed registry** (the `scanner_nodes` table) that the admin
manages via `GET/POST/PUT/DELETE /api/nodes` (reads: viewer; writes: admin) or a
service-account script. The DB is the system of record — nodes never call the backend, so the
one-way boundary (traffic strictly backend→node, node holds no DB credentials) is intact.

A node is `{ name, endpoint, token, cidrs[], tags[] }`. It runs scans whose target IPs fall in
its `cidrs`; a node with **no** CIDRs is a **catch-all** for hostname targets (matching is
DNS-free, like the scope guardrail) and IPs matching no other node.

**Config seeds the registry on first boot only.** `SCANNER_URL`/`SCANNER_TOKEN` seed a catch-all
node named `default`; optional `SCAN_ZONES` (a JSON array) seeds CIDR-mapped nodes for segmented
networks:

```json
[
  {"name":"corp","cidrs":["10.0.0.0/8"],"url":"http://scanner-corp:8081","token":"…"},
  {"name":"dmz","cidrs":["192.168.1.0/24"],"url":"https://scanner-dmz:8081","token":"…",
   "tls_server_ca":"-----BEGIN CERTIFICATE-----\n…","tls_client_cert":"…","tls_client_key":"…"}
]
```

A zone may also carry the optional per-node mTLS material (`tls_server_ca` / `tls_client_cert` /
`tls_client_key`) to bootstrap a segmented node over mTLS from config — see
[Service auth: TLS & mTLS](#service-auth-tls--mtls).

- **Seed-only:** at startup a config entry is inserted **only if its name is not already in the
  DB**. An admin's edit to a node always survives restart; editing the config file afterward only
  ever *adds* new, non-overlapping nodes — it never updates or deletes (a divergent config entry
  logs a drift warning, DB wins). The file is for standing up a working environment without
  scripting, not an ongoing control surface.
- **Dispatch** routes a scan to the node whose CIDRs contain the target's IP. Node CIDRs are
  **non-overlapping** (enforced on every API write with a 400, and on a config seed by
  skip-with-warning; overlaps *within one node's* CIDR list are fine), so at most one node matches
  — no round-robin. Targets that match no node use a catch-all.
- All IP targets of a scan must resolve to the **same** node; a scan spanning two nodes is
  rejected (split it). Overlaps *within the config file itself* still fail fast at startup.
- Deleting the **last** catch-all node is refused, so hostname targets always have somewhere to go.

**Health (#98):** the backend polls each node's `GET /v1/capabilities` every `NODE_HEALTH_INTERVAL`
(strictly backend→node) to derive liveness. `GET /api/nodes` reports per node `healthy`
(`null` = not yet polled), `last_seen`, and `nuclei_version`. A node stays healthy for 3× the
interval after its last successful poll, then flips. Dispatch **fails a scan fast** with a clear
error when its matching node is known-unhealthy, rather than dispatching into a black hole; a
not-yet-polled node dispatches optimistically. Liveness is in-memory only (recomputed from the last
poll — never persisted, invariant #4).

The **nodes admin UI** (#99) lets an admin manage this registry — and each node's mTLS material
(below) — under **Scanner Nodes**.

## Service auth: TLS & mTLS

The backend→scanner path authenticates with a shared bearer token (`SCANNER_TOKEN`) over the
transport. For nodes in an **untrusted network segment**, upgrade that transport to **mutual TLS**
so a node accepts dispatch only over a mutually-authenticated connection — the bearer token still
applies on top (defense in depth).

**On the node** (serve HTTPS, then require client certs) — process env, since the scanner isn't in
the registry:

- `SCANNER_TLS_CERT` + `SCANNER_TLS_KEY` — the node's server certificate; setting both switches the
  node from HTTP to HTTPS.
- `SCANNER_CLIENT_CA` — a PEM CA bundle. When set, the node requires **and verifies** a client
  certificate (`RequireAndVerifyClientCert`): a client without a valid cert is rejected at the TLS
  handshake, before any request is served.

**On the backend** (present a client cert, pin the node) — **per node in the registry** (#26), set
via the API/UI (or seeded from `SCAN_ZONES`), so different segments can use different certs:

- `tls_server_ca` — a PEM CA bundle to verify (pin) the node's server certificate; optional (falls
  back to the system roots).
- `tls_client_cert` + `tls_client_key` — the client certificate the backend presents to this node.
  Provide both together. The **key is a write-only secret** (like the bearer token): never returned
  by the API, and blank on edit keeps the stored one. The CA and client cert are public and are
  returned on reads. Point the node's endpoint at `https://…` to actually use them.

Leaving a node's TLS fields empty keeps the current plain-HTTP + bearer-token behavior for that
node. A broken keypair (or an unreachable HTTPS endpoint) surfaces as an **unhealthy** node with the
TLS error in the nodes UI, rather than a silent dispatch failure. Certificate **issuance and
rotation** are a deployment concern (a mesh CA, cert-manager, or SPIFFE/SPIRE); in a **service
mesh** the sidecar can terminate mTLS instead, in which case leave these unset and let the mesh
handle it — the app code is unchanged either way.

## Container images

Both images build on **Red Hat UBI 10 Micro** — a minimal, security-hardened base with a long
enterprise support window and no package manager/shell — and publish as **multi-arch manifest
lists** for `linux/amd64` and `linux/arm64` (so they run on ARM hosts like AWS Graviton or
Apple-silicon runners without a second image). The Go binaries are cross-compiled with
`CGO_ENABLED=0` (static, no glibc surprises) from the native build platform, so nothing runs under
emulation.

UBI 10 Micro ships **no CA trust store** at all, so **both** images copy a CA bundle to
`/etc/ssl/certs/ca-certificates.crt` for outbound TLS. The **backend** needs it for Postgres / OIDC
IdP / S3 (and runs as a non-root user); the **scanner** needs it for Nuclei's target/OOB/interactsh
TLS.

The **scanner image** bakes in the pinned execution binaries but no community template cache:
the backend-owned active catalog bundle is the only template source a scan may use.

- **Pinned, checksum-verified `nuclei`** — a build stage downloads the release asset and **verifies
  its SHA-256 against the release checksums file** before copying just the `nuclei` binary onto the
  runtime (on `PATH`, so `NUCLEI_PATH=nuclei` still works). This removes the trust dependency on a
  mutable upstream image tag. The same pinned binary authoritatively validates custom-template
  create/update requests and selected custom writes from an archive import (one process per batch):
  the backend selects a node already known healthy from `NODE_HEALTH_INTERVAL` polling and fails
  the write with `503` if no validator is available.
- **Bundle-only templates** — before dispatch, the backend pushes the full active catalog when the
  node is stale. Each scan carries concrete ids + the bundle digest; the node resolves every id
  from `manifest.json`, rejects missing ids/drift, and holds a shared lock on the active tree until
  Nuclei exits. There is no `nuclei -update-templates` path.

| Build arg | Image | Default | Purpose |
| --- | --- | --- | --- |
| `NUCLEI_VERSION` | scanner | **pinned in `deploy/Dockerfile.scanner`** | nuclei release baked into the image. This `ARG` is the **single source of truth** — CI does not override it. Bumping nuclei = bump this (per architecture invariant #3, nuclei is a binary, not a linked SDK). |

To upgrade nuclei, change the `ARG NUCLEI_VERSION` default in `deploy/Dockerfile.scanner`, or
override per-build:

```sh
docker buildx build -f deploy/Dockerfile.scanner \
  --platform linux/amd64,linux/arm64 \
  --build-arg NUCLEI_VERSION=3.11.0 -t scanner .
```
