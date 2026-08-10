# Administration guide

This guide covers deploying and operating Nuclei Security Center (NSC). For endpoint-level details,
see the [API reference](API.md); for design rationale and security boundaries, see
[Architecture](ARCHITECTURE.md).

> [!IMPORTANT]
> The beta supports **fresh deployments only**. Alpha databases are not upgradeable. Back up any
> data you need to retain, deploy with a new empty Postgres database, and move portable data with
> template/template-set exports and scan bundles. The backend rejects an alpha migration history at
> startup instead of attempting a partial upgrade.

## 1. Deployment

### Requirements

NSC needs:

- the backend and one or more scanner containers;
- PostgreSQL 16 or newer;
- an OIDC provider for production authentication;
- an S3-compatible object store if raw scan-output and execution-log archival is required; and
- network paths from the backend to every scanner, and from each scanner to its assigned targets.

The scanner holds no database credentials. Traffic is backend → scanner only; scanner nodes never
register with or call the backend. Keep scanner egress restricted to the networks each node is
intended to scan.

### Local Docker Compose deployment

```sh
cp .env.example .env
# Change SCANNER_TOKEN. Keep the seeded OIDC secret unless you update the realm too.
docker compose up --build
```

The seeded Keycloak client secret in `deploy/keycloak/realm-nsc.json` matches `.env.example`.
For local development, either leave that development-only `OIDC_CLIENT_SECRET` unchanged or,
before Keycloak first imports the realm, set the same replacement value in both `.env` and the
realm JSON. Changing only `.env` makes the OIDC callback's token exchange fail. If Keycloak already
imported the realm, recreate its Compose container after synchronizing both values (`docker compose
down`, then `docker compose up --build`); local Keycloak data lives in the container layer.

Open <http://localhost:8080>. The compose stack includes Postgres, MinIO, Keycloak, one scanner,
and the backend/SPA. Demo users use their username as the password:

| User | Role |
|---|---|
| `admin` | admin |
| `operator` | operator |
| `viewer` | viewer |

Keycloak's local admin console is at <http://localhost:8082> (`admin` / `admin`). These seeded
credentials and the compose defaults are for local development only.

A fresh backend creates `schema_migrations`, applies the single beta baseline, seeds the configured
default scanner node, and starts the scheduler, template sync/distribution, node-health monitor,
and retention sweeper.

### Production deployment

1. Provision an empty PostgreSQL database and a bucket (optional but recommended).
2. Deploy one scanner per reachable network zone. Give every scanner a strong, distinct bearer
   token and TLS; use mTLS for untrusted segments.
3. Deploy the backend with Postgres, OIDC, object-store, and initial scanner seed configuration.
4. Terminate browser TLS at the backend or an ingress and keep `COOKIE_SECURE=true`.
5. Send backend stdout to the platform log aggregator; that is the audit trail.
6. Verify `/healthz`, sign in, and complete the [first-run bootstrap](#4-first-run-bootstrap).

The images are multi-architecture (`linux/amd64`, `linux/arm64`) Red Hat UBI 10 Micro images. The
scanner image contains pinned, checksum-verified `nuclei` and `naabu` binaries; scanner upgrades are
image upgrades, not in-place binary updates.

## 2. Environment-variable reference

All configuration is environment-based. Required values fail fast. Go-duration values use forms
such as `30s`, `15m`, and `6h`.

### Backend

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

`SCAN_ZONES` uses this JSON shape (the three PEM-valued TLS keys are optional):

```sh
export SCAN_ZONES='[{"name":"dmz","url":"https://scanner-dmz:8081","token":"replace-with-a-strong-token","cidrs":["10.20.0.0/16"],"max_concurrent_scans":4,"tls_server_ca":"<PEM CA>","tls_client_cert":"<PEM client certificate>","tls_client_key":"<PEM client key>"}]'
```

Use escaped `\n` characters inside JSON strings when embedding multiline PEM values. Seed entries
are insert-only by node name; PostgreSQL and subsequent API/UI edits are authoritative.

### Authentication and sessions

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
| `SESSION_TTL` | `12h` | Server-side session lifetime. |
| `SESSION_COOKIE_NAME` | `nsc_session` | Session cookie name. |
| `COOKIE_SECURE` | `true` | Secure-cookie flag. Set `false` only for local plaintext HTTP. |

### Object storage

| Variable | Default | Purpose |
|---|---|---|
| `S3_ENDPOINT` | unset (archiving disabled) | S3-compatible endpoint as `host:port`, without a scheme. |
| `S3_BUCKET` | `nuclei-raw` | Archive bucket; created at startup when absent. |
| `S3_ACCESS_KEY_ID` | unset | Static access key. Leave empty to use the ambient AWS credential chain. |
| `S3_SECRET_ACCESS_KEY` | unset | Static secret key. |
| `S3_REGION` | `us-east-1` | S3 region. |
| `S3_USE_SSL` | `false` | TLS for the S3 endpoint. Enable in production. |

The backend archives byte-exact raw Nuclei output and execution logs best-effort. PostgreSQL remains
the system of record: an archive upload failure is logged but does not discard successfully ingested
findings. Downloads are proxied through the authenticated backend; NSC does not expose presigned
URLs.

### Scanner

| Variable | Default | Purpose |
|---|---|---|
| `SCANNER_ADDR` | `:8081` | Node listen address. |
| `SCANNER_TOKEN` | required, minimum 32 characters | Bearer token accepted from the backend. Use a distinct secret per node where possible. |
| `NUCLEI_PATH` | `nuclei` | Nuclei executable. The image already supplies the pinned binary. |
| `NAABU_PATH` | `naabu` | Naabu executable used by discovery-enabled policies. |
| `NAABU_SCAN_TYPE` | `syn` | Node default (`syn` or `connect`) when a policy does not choose. SYN needs raw sockets and libpcap; connect is the unprivileged fallback. |
| `SCANNER_WORK_DIR` | private `0700` temporary directory | Per-scan work root. If set, mount a private node-local volume. |
| `SCANNER_TLS_CERT` | unset | PEM server certificate. Must be paired with `SCANNER_TLS_KEY`. |
| `SCANNER_TLS_KEY` | unset | PEM server private key. |
| `SCANNER_CLIENT_CA` | unset | CA bundle used to require and verify backend client certificates (mTLS). |
| `SCANNER_MAX_CONCURRENT_SCANS` | `20` | Standalone-node fallback admission limit (`1`–`100`) used only when a direct node caller omits the backend registry value. Normal backend dispatch sends the per-node value from PostgreSQL. |

## 3. Authentication, service accounts, and transport security

### OIDC/BFF

NSC is a confidential OIDC client. Tokens stay in the backend; browser JavaScript receives only an
httpOnly, SameSite session cookie. Map the configured claim to `admin`, `operator`, and `viewer`.
Reads require viewer, scan/config mutations generally require operator, and destructive/fleet
administration requires admin.

Register the exact `OIDC_REDIRECT_URL` with the provider. If browser-facing and cluster-internal
issuer addresses differ, keep the canonical browser issuer in `OIDC_ISSUER` and use
`OIDC_DISCOVERY_URL` for backend metadata requests.

### Headless automation

Admins can create role-scoped, revocable NSC service-account tokens. Automation sends:

```http
Authorization: Bearer <token>
```

Use the least-privileged role, set an expiry where practical, rotate the token through the service
account API/UI, and revoke it independently of human IdP access. See
[API → Service accounts](API.md#service-accounts).

### Backend-to-scanner TLS and mTLS

Bearer authentication always applies. For an untrusted segment:

1. Configure `SCANNER_TLS_CERT` and `SCANNER_TLS_KEY` on the node.
2. Set `SCANNER_CLIENT_CA` to require a backend client certificate.
3. In **Scanner Nodes**, configure that node's endpoint as `https://…`, pin its server CA, and store
   the backend client certificate/key.

The per-node client key and bearer token are write-only in API responses. Certificate issuance and
rotation remain deployment concerns; a service mesh may terminate mTLS instead.

## 4. First-run bootstrap

1. **Sign in as admin.** Confirm `/api/auth/me` shows the expected role mapping.
2. **Check Scanner Nodes.** The seeded default node starts as unknown, then should become healthy
   after the first capability poll and report its Nuclei version.
3. **Sync templates.** Open **Templates → Sync** and run the first upstream refresh. The initial
   community-repository clone is large; later runs reuse `TEMPLATE_SYNC_DIR`.
4. **Verify the catalog.** Confirm the sync run succeeded and the Catalog tab contains active
   templates. Removed upstream templates are retained as unavailable for explainability.
5. **Push the node bundle.** Automatic distribution handles this, but **Sync templates** on the node
   is a useful first-run verification. The node and catalog digests should match.
6. **Create the operating chain:** target → template set → scan policy → manual scan. Add a schedule
   only after the manual scan completes successfully.
7. **Verify archives and audit logs.** Download raw output/execution logs when object storage is
   enabled and confirm mutating actions appear as structured `event=audit` records in stdout.

Custom template writes intentionally fail with `503` until at least one validator node is known
healthy.

## 5. Day-to-day operations

### Targets: define approved scope

Create named targets from hostnames, IPs, CIDRs, or URLs. Target validation is DNS-free and
host-granular. Every launch selects a stored target, so there is no API path for an arbitrary host.
Review `host_count` before scanning: a `/24` counts as 256 addresses, not one list item.

Deleting a target removes its future schedules and nulls links on historical scans; it does not
delete scan history.

### Template catalog and custom templates

- **Upstream templates** are sync-owned and read-only.
- **Custom templates** are stored losslessly in PostgreSQL.
- Every custom create/update is sent to a healthy scanner's pinned `nuclei -validate` before the
  transaction commits. Invalid YAML returns bounded diagnostics; validator unavailability returns
  `503`, and nothing is persisted.
- Sync history is retained and shows added, updated, removed, skipped, digest, and template count.
- A template removed upstream becomes unavailable rather than disappearing from history.

Upgrade Nuclei by rebuilding/deploying the scanner image with the pinned version, then verify node
capabilities and custom-template validation.

Routine template administration follows this workflow:

1. An **operator** runs upstream sync and reviews the recorded sync result.
2. An **operator** creates or updates custom YAML; a healthy scanner validates it before commit.
3. An **operator** creates an `exact`, `all`, or `exclude` set and verifies its effective members.
4. An **admin** pushes/syncs the current catalog bundle to nodes; viewers may inspect status.
5. A **viewer** may export templates/sets, while an **operator** may import with `skip`, `overwrite`,
   or deterministic `rename` conflict handling.

### Template sets

Choose the mode deliberately:

| Mode | Behavior |
|---|---|
| `exact` | Stores explicit template IDs. Best for tightly controlled/reproducible policy selection. |
| `all` | Resolves every active template at dispatch. Follows catalog growth automatically. |
| `exclude` | Resolves every active template except an explicit deny-list. |

Empty exact sets and exclude sets that resolve to zero templates fail closed. Exact sets containing
unavailable IDs must be repaired before dispatch. A custom template referenced by an exclude-set
deny-list cannot be deleted until that exclusion is removed, preventing accidental re-enablement.

Catalog/templates and sets export as lossless YAML archives or JSON. Imports support `skip`,
`overwrite`, and deterministic `rename` conflict policies. All selected custom writes are validated
in one bounded batch and committed atomically; one invalid file prevents the entire selected batch.

### Scan policies

A policy is reusable **how to scan** configuration. It selects one template set and optional Nuclei
and discovery knobs. The target is selected independently at launch/schedule time, allowing one
policy to run across multiple approved scopes.

Discovery is enabled by default unless a policy disables it. Naabu narrows targets to open
`host:port` pairs before Nuclei. SYN mode is fastest on suitable Linux networking; connect mode is
an unprivileged fallback. Discovery errors/timeouts fail the scan closed rather than silently
running Nuclei against the unfiltered range.

### Schedules

A schedule combines a policy, target, and cron expression. PostgreSQL stores enablement and next/last
run state. The scheduler wakes each minute; a run missed while the backend was down fires once after
restart and then advances normally. **Run now** performs an off-cycle dispatch without changing the
cadence.

Use case-insensitively unique names and pause a schedule before changing a target/policy with broad
scope.

### Scanner fleet

The scanner registry in PostgreSQL is authoritative. `SCANNER_URL` and `SCAN_ZONES` only seed names
that do not exist; they never overwrite admin edits or delete nodes.

- CIDR assignments must not overlap across nodes.
- A node with no CIDRs is the catch-all for hostnames and unmatched IPs.
- All IP targets in one scan must map to the same node.
- Deleting the last catch-all is refused.
- `max_concurrent_scans` is configured independently per node in **Scanner Nodes**. It bounds both
  backend polling goroutines and node-side scan admission; a capacity rejection returns HTTP `429`
  and does not create a scan row. The default is `20`, with a hard range of `1`–`100`.
- Dispatch fails fast when the selected node is known unhealthy.
- Bundle distribution targets only stale, idle nodes; a busy node may return `409` until its scan
  releases the active template tree.

## 6. Findings, triage, exports, and scan bundles

NSC keeps immutable per-scan **occurrences** and a globally deduplicated **finding lifecycle**.
Detection state is derived from scan evidence:

| State | Meaning |
|---|---|
| `new` | First observation. |
| `active` | Still observed and never previously mitigated. |
| `resurfaced` | Previously mitigated, now observed again. |
| `mitigated` | Absent from the latest scan that proved the exact template reached the exact endpoint. |
| `previously_mitigated` | Flapped: mitigated, resurfaced, and absent again. |

Closure is evidence-driven; there is no manual “fixed.” Missing/invalid request-trace coverage fails
closed, and a completed scan that skipped malformed or oversized finding records cannot provide
negative mitigation evidence. Analysts may apply `false_positive` or optionally time-bounded `accepted` dispositions and
recast severity.

The lifecycle list exports as JSON, CSV, SARIF, or raw Nuclei JSONL with the same filters used in the
UI. Raw lifecycle export uses the latest occurrence; the per-scan object archive remains the
byte-exact scanner output.

A scan bundle exports one complete scan result as JSON or zip, including its config snapshots,
resolved template IDs/digest, coverage, and occurrences. It intentionally excludes analyst
lifecycle overlays. Import recomputes identity and derives lifecycle state on the destination; use
bundles to move scan results between fresh deployments.

## 7. Audit logging

Every mutating API request emits one structured log record to backend stdout with `event=audit`.
Records include actor and actor type, action, object type/id, HTTP status, duration, and a stable
`event_id`. Dispatch events also include policy, target, and scan IDs; unattended schedules use
`actor_type=system`.

There is deliberately no audit table in PostgreSQL. Configure the platform log collector for:

- durable retention and access control;
- searches/alerts on `event_id` such as `access_denied`, `config_changed`, `scan_dispatched`,
  `finding_triaged`, and `service_account_changed`;
- detection of repeated denied access, unexpected scope changes, and service-token changes; and
- protection against application/database administrators rewriting historical audit records.

## 8. Backups, retention, and upgrades

- Back up PostgreSQL using the managed service's native snapshots/PITR. It contains configuration,
  scan records, occurrences, lifecycle state, sessions, and template catalog.
- Apply bucket lifecycle/backup policy separately for raw archives and execution logs.
- Configure scan retention in **Settings**. The policy is DB-backed; `RETENTION_SWEEP_INTERVAL` only
  controls polling frequency.
- Back up custom templates/template sets with portability exports and scan results with bundles when
  moving environments.
- Rotate DB credentials through `DATABASE_PASSWORD_FILE` using a secret-rendering sidecar/agent.
  Leading/interior whitespace is preserved and trailing CR/LF is trimmed.
- Future beta migrations are ordered and checksum-immutable. Never edit an applied migration; add a
  new numbered forward migration.
- Do not point beta at an alpha database. The startup rejection is intentional; deploy fresh.

## 9. Troubleshooting

| Symptom | Meaning / action |
|---|---|
| Backend reports unsupported migration versions or a missing checksum | The database is from alpha. Preserve exports/backups as needed and deploy beta against a new empty database. |
| Backend cannot reach Postgres | Verify `DATABASE_URL`, TLS/network policy, credentials, and the password-file contents/permissions. |
| Login loops or callback fails | Match `APP_BASE_URL`, `OIDC_ISSUER`, and registered `OIDC_REDIRECT_URL`; use `OIDC_DISCOVERY_URL` only for internal metadata routing. |
| Session works locally but not through ingress | Keep HTTPS end-to-end or at the ingress and verify `COOKIE_SECURE=true`, forwarded host/scheme, and the public base URL. |
| Node remains unknown/unhealthy | Check backend→node DNS/routing, endpoint scheme, bearer token, TLS CA/client pair, and `/v1/capabilities`. |
| Custom template returns `400` | Fix the Nuclei YAML using the returned diagnostics; nothing was persisted. |
| Custom template/import returns `503` | No known-healthy validator completed the request. Restore node health/token/TLS/Nuclei availability and retry. |
| Upstream sync is disabled | Set `TEMPLATE_SYNC_REPO`, or intentionally run a custom-only catalog. |
| First template sync is slow | The first clone is large. Persist `TEMPLATE_SYNC_DIR`; later runs fetch deltas. |
| Manual node sync returns `409` | A scan is using the active tree. Wait for it to finish. |
| Template ID/digest drift blocks dispatch | Sync the current catalog to the selected node and verify its persistent work storage. The refusal preserves reproducibility. |
| Custom deletion returns `409` | Remove the template from exclude-set exclusions first. |
| Policy cannot use a set | Populate an empty exact set, replace unavailable IDs, or ensure an exclude set does not exclude the entire active catalog. |
| Discovery fails with permission/libpcap errors | Use the scanner image with required libraries/capability, or set the policy/node to connect mode. |
| Docker Desktop reports every private-CIDR host alive | macOS VM/NAT can distort SYN host-discovery tally. Trust persisted discovered endpoints, use connect mode for local development, or verify SYN behavior on Linux/routable networks. |
| Archive endpoint returns `404` | `S3_ENDPOINT` is unset, the scan has no archive, or the object is unavailable. |
| Object upload logs warnings but scan completes | Archival is best-effort by design; repair endpoint/credentials/bucket policy and test a new scan. |
| A finding does not auto-mitigate | Confirm a later complete scan ran the same template and request-trace evidence reached the same normalized host:port without skipped ingest. Missing coverage fails closed. |

For HTTP status codes and request/response shapes, continue with the [API reference](API.md).
