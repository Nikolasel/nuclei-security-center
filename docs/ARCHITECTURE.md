# Nuclei Security Center — Architecture

**Scope:** internal tool for a small security/eng team. Multi-user, auth required, no
formal regulatory framework driving design. Must be **easy to run on any cloud**.

The guiding constraint is *cloud portability*, which is the main thing that steers this
design away from the "use the hyperscaler's native scheduler/queue" advice: native
services save build effort but lock you to one cloud. We instead build a self-contained
stack that runs identically via Docker Compose locally and on managed Postgres +
containers (ECS / Cloud Run / any Kubernetes) in the cloud.

---

## 1. Design principles

1. **Portable core, pluggable edges.** Only hard dependencies are *containers*,
   *Postgres*, and an *S3-compatible object store*. Everything cloud-specific
   (secrets, storage endpoint, IdP) sits behind a small interface.
2. **Keep infra boring and few.** No Redis, no dedicated queue broker, no external
   scheduler for the MVP — Postgres does queue + schedule duty via `SELECT ... FOR
   UPDATE SKIP LOCKED`. One fewer moving part to run, secure, and pay for.
3. **Nuclei stays a black box we drive, not a library we embed.** The worker shells
   out to the `nuclei` binary. Upgrading Nuclei = swap the binary/image; no code change.
   (The Go SDK is an option — see §7 trade-offs — but coupling to its API costs more
   than it saves here.)
4. **The UI's value is lifecycle, not re-running Nuclei.** Raw Nuclei gives you a flat
   list per run. The product value is *dedup + first-seen/last-seen + new-since-last-scan
   + triage state*. That's the core data model, not an afterthought.

---

## 2. Components

Three deployable services, split so the scanner node is a pure, disposable execution
engine that holds **no database credentials** — it only ever receives a scan spec and
returns results.

```
   user browser
        │  1. OIDC login   2. httpOnly session cookie
        ▼
   ┌───────────────────────────┐
   │   SPA (React + TS + Vite) │
   └────────────┬──────────────┘
                │  JSON/REST, session cookie
                ▼
   ┌───────────────────────────┐   dispatch scan spec (Bearer service token, TLS)
   │  Backend (Go)             │ ─────────────────────────────┐
   │  BFF: OIDC client +       │                              ▼
   │       server-side session │        ┌────────────────────────────────────┐
   │  system of record (PG)    │        │  Scanner node(s) (Go)              │
   │  findings lifecycle/dedup │  poll  │  API-token auth, NO DB creds       │
   │  scheduler + dispatch     │ ◀──────│  sync tmpl ─▶ naabu ─▶ nuclei ─▶   │
   │  RBAC + audit log         │ results│  serve JSONL results (pull-only)   │
   └────────────┬──────────────┘        └────────────────────────────────────┘
                ▼
        Postgres + S3-compatible store
        (system of record, template catalog + raw output)
```

Scanner nodes deploy **1..N**, optionally one per network zone — a `target` record
selects which zone can reach it, so a segmented scanner never sees out-of-zone hosts.

| Component | Choice | Why |
|---|---|---|
| Frontend | **React + TypeScript + Vite** SPA | Modern SPA calling the backend API; rich interactivity for findings triage |
| Backend | Go, single static binary | System of record + API + OIDC BFF; cohesive with the Nuclei ecosystem |
| Scanner node | Go, standalone HTTP service | Pure execution engine; holds no DB creds; scale/segment independently |
| DB | Postgres | Data + schedule + backend-side dispatch queue in one service |
| Object store | S3-compatible behind one interface | MinIO locally → S3/GCS/Azure Blob in cloud, no code change |
| Templates | Lossless Postgres catalog → pushed node bundle | Backend owns upstream/custom content; scans select ids from a content-addressed full-catalog bundle |
| User auth | OIDC via BFF (Cognito / Entra / Keycloak) | SSO everywhere; tokens stay server-side, SPA gets only a session cookie |
| Service auth | API bearer token (TLS); mTLS as upgrade | Backend → scanner-node calls, no user identity involved |

---

## 3. Data model (core tables)

- **users** — `id, email, role` where role ∈ `admin | operator | viewer`.
- **targets** — `id, name, hosts[] (CIDRs/URLs), tags[], created_by`. Targets are the
  **scope allowlist** — scans can only hit pre-approved hosts (guardrail, see §6).
- **templates** — lossless source YAML plus indexed metadata (`id, source, path, name, author,
  severity, description, tags, content_sha256`). The raw YAML is the sole complete
  representation; metadata is extracted only for catalog filtering.
- **template_sync_runs** — backend-owned upstream catalog refresh history, including pinned
  commit and added/updated/removed/skipped counts (a stray malformed file is skipped-and-counted,
  not fatal; the run fails closed only if nothing parses).
- **template_sets** — curated explicit membership in `template_set_members`. The retired filter
  columns are gone. Pre-existing POC rows retain a read-only JSON filter snapshot and fail closed
  until an operator atomically converts the snapshot against the current active upstream catalog.
  Sets and selected templates are portable as either a lossless YAML tarball (verbatim files +
  manifest) or one JSON document retaining the verbatim YAML strings. Import writes custom
  templates and set membership atomically; upstream rows remain sync-owned and are reference-only.
- **scan_policies** — `id, name, target_id, template_set_id, rate_limit, concurrency,
  timeout_sec, max_host_error`. The **central, reusable scan configuration**: it bundles
  *everything* a scan needs — the target (required — the scope), an optional template set
  (NULL = all templates), and Nuclei's execution knobs (each nullable = "use the built-in
  default"). **Every scan and schedule is launched by selecting a policy.** Deleting a policy's
  target cascades the policy away; deleting a template set nulls it back to "all templates".
- **schedules** — `id, scan_policy_id, cron, enabled` — a policy paired with a cadence. Deleting
  the policy cascades the schedule away.
- **scans** — `id, source (schedule|adhoc), scan_policy_id, target_id, template_set_id, status,
  started_at, finished_at, nuclei_version, templates_commit, triggered_by`. The policy's target/
  template set are resolved and recorded on the scan at dispatch (so findings keep working and
  history survives `scan_policy_id` being nulled on policy delete — `ON DELETE SET NULL`).
- **findings** (occurrences) — the immutable per-scan observation log: `id, scan_id,
  target_id, dedup_key, template_id, name, severity, host, matched_at, raw_json`. Answers
  "what did scan X observe"; feeds the raw archive in object storage.
- **finding_lifecycle** — the **deduplicated, triageable** entity keyed on
  `(target_id, template_id, matched_at)` so lifecycle survives across scans. Models a
  **Tenable Security Center-style** two-dimensional lifecycle:
  - *Detection state* — **derived at read time** from scan observation, never stored:
    **New / Active / Resurfaced** (cumulative — still detected) and **Mitigated /
    Previously Mitigated** (no longer detected). `times_mitigated` (maintained at ingest)
    distinguishes a first disappearance from a flapping one. **Closure is
    evidence-driven — there is no manual "fixed."**
  - *Disposition* — the analyst overlay (the only manual state): **Accept Risk** (with an
    optional `accept_expires_at` — an expired acceptance falls back to its detection
    state) and **False Positive**, plus **Recast Risk** (a `recast_severity` override).
    Each carries a note/actor/timestamp audit trio.
  - The **effective state** (what the UI shows) overlays disposition on detection:
    accepted / false_positive win, else the detection state.
There is deliberately **no `audit_log` table**: the audit trail is emitted as structured
`event=audit` log lines to stdout for the platform's log aggregator, not stored in the app DB
(see §6). Keeping it off the database means a DB compromise can't rewrite the trail.

---

## 3a. Datastore choice (SQL vs NoSQL for findings)

The system has **two data shapes**, and they want different things:

- **Config / transactional core** (users, targets, schedules, scans state machine,
  audit) — relational, needs transactions + read-your-writes + the `SKIP LOCKED`
  dispatch queue. → **Postgres, non-negotiable.**
- **Findings** — semi-structured JSON, higher volume, search/filter/aggregation heavy.
  This is the only part where NoSQL is genuinely tempting.

Decision for findings:

| Option | Verdict |
|---|---|
| **Postgres `JSONB` (GIN + `pg_trgm`)** | **Chosen for MVP.** Stores variable-shape finding docs, queries + FTS into them, one store, transactions, fully portable. |
| Postgres + **OpenSearch as a *derived* index** | The scale answer if findings search/volume ever outgrows Postgres. Postgres stays source of truth; OpenSearch would be a search projection synced at ingest. Not on the roadmap — the tool is scoped to a small internal team and is not expected to reach the volume where this pays off (#21). |
| OpenSearch as the **only** store | Rejected — it's a search index, not a system of record (no ACID, near-real-time, reindexing pain). Bad fit for the queue/audit. |
| MongoDB as the **only** store | Rejected — trades the relational core's natural fit + SQL ergonomics for document flexibility `JSONB` already provides. Net-neutral. |

Two things de-risk staying on Postgres now:
1. **Raw `out.jsonl` → object storage** is the immutable archive; the DB only holds the
   *parsed/indexed* findings, so nothing is lost if we later reshape the query store.
2. The findings **read/search path sits behind an interface**, so OpenSearch drops in as
   a derived index with no change to callers.

Scale check: a small team scanning its own estate accumulates ~tens of thousands of
finding rows (active set kept smaller by lifecycle dedup) — comfortably within Postgres.
OpenSearch's operational weight pays off around the 10M-doc / heavy-aggregation range.
And since the UI is a custom SPA, we don't need Kibana/OpenSearch Dashboards.

---

## 4. Scan orchestration flow

Push model: the **backend dispatches** to a scanner node's API (no worker-pull queue).
The backend keeps a lightweight `queued → dispatched → running → complete` state machine
so scans survive a busy or briefly-unreachable node.

1. **Trigger** — a schedule's cron fires (backend ticker) *or* a user clicks "Run now."
   A `scans` row is inserted with status `queued`.
2. **Resolve + top up** — the backend resolves the policy's template set to concrete
   catalog ids (or every active id when the policy has no set), computes the full active
   catalog's canonical `templates_commit`, and records both in the scan spec. Before
   dispatch it picks the target's node and pushes the full catalog if any selected
   template changed since `templates_synced_at` **or** the node's freshly reported
   `templates_commit` differs (self-heals a wiped node).
3. **Dispatch** — the backend calls `POST /v1/scans` with targets, `template_ids`,
   `templates_commit`, and execution options. The node resolves every id through the
   active bundle's manifest and rejects the request if any id is missing or the commit
   differs. A running scan holds a shared lock on the active tree for its whole life;
   activation uses a fail-fast exclusive lock and returns `409` while a scan runs.
   On `202` the backend records the node's `scan_id` and marks the scan `running`.
3a. **Discover (on node, optional — #86)** — when the scan spec's `options.discovery`
   is enabled (default on, set per scan policy), the node first runs **naabu** as a
   port-scan pre-pass over the target hosts and narrows Nuclei's input to the live
   `host:port` pairs it finds. This is the win for CIDR-scoped targets: instead of
   Nuclei probing all 256 addresses of a `/24` for every template, it only touches
   what's actually listening. By default naabu runs a **SYN scan preceded by host
   discovery** (`-scan-type syn -with-host-discovery`, probing ICMP echo *and* TCP
   SYN/ACK to 80/443 so a host that blocks ping but serves the web is still found
   alive): host discovery prunes dead hosts before port-scanning, the big win on sparse
   ranges. This needs raw sockets (`CAP_NET_RAW`, in Docker's default capability set) and
   **libpcap** (the hardened `ubi10-micro` runtime image copies in libpcap + its shared-lib
   closure, staged from a `ubi10-minimal` builder — see `deploy/Dockerfile.scanner`).
   A scan policy can pick the mode per-scan (`discovery_scan_type` = `syn`|`connect`);
   unset, it uses the node's `NAABU_SCAN_TYPE` default. Connect is an unprivileged TCP
   connect scan with no host discovery — no capabilities or libpcap, but slower (it scans
   every host) — for deployments that drop `NET_RAW`; requesting `syn` on such a node fails
   the scan closed. Note connect still narrows Nuclei to the open ports it finds; it only
   loses the dead-host pruning, so it is faster than disabling discovery outright. Discovery has
   its **own timeout budget**
   (separate from the Nuclei `timeout_sec`) and scans naabu's top-1000 ports by default
   (a policy can set an explicit port spec, including multiple ranges). It **fails
   closed**: a naabu error/timeout fails the scan rather than silently falling back to
   an unfiltered run, so a broken discovery is disabled deliberately on the policy. A
   clean run that finds no open ports simply completes with no findings — there is
   nothing for Nuclei to probe. naabu stays a **binary we drive**, like Nuclei (bump
   the image to upgrade). Its stderr is captured into the same execution-log archive
   (#94) as Nuclei's. The discovering-phase host count is read from naabu's stderr, so
   it is only as accurate as naabu's view of the network — on Docker Desktop (macOS) the
   NAT layer makes every address in a private range appear alive, so the live tally is
   not a verification of network aliveness in dev (the authoritative narrowed set is the
   persisted `discovered_targets`; see [Development](DEVELOPMENT.md#discovery-on-docker-desktop-macos-reports-every-host-as-alive)).
4. **Run (on node)** — `nuclei -l targets.txt -t <paths> -jsonl -o out.jsonl` plus the
   rate-limit / concurrency / timeout flags from the spec. When discovery ran,
   `targets.txt` is the narrowed `host:port` list from step 3a.
5. **Poll for results** — the backend polls `GET /v1/scans/{id}` for status/progress,
   then pulls `GET /v1/scans/{id}/results` (NDJSON stream) once the node reports
   `complete`. Pull-only: the flow is strictly backend → node, and in-flight scans resume
   from Postgres if the backend restarts. No node → backend inbound path exists.
6. **Ingest (on backend)** — the backend parses the JSONL and upserts `findings`,
   updating `first_seen`/`last_seen` and flipping resolved findings not seen this run.
   **All dedup/lifecycle lives here** — the node stays stateless.
7. **Persist** — upload raw `out.jsonl` (+ optional SARIF) to object storage; mark scan
   `complete`; write audit entries.
8. **Failure path** — node timeout/non-zero exit, or dispatch/poll failure → status
   `failed`, capture stderr tail and the reason.

---

## 4a. Scanner node API (service-to-service, Bearer token over TLS)

The node is a small, self-contained HTTP service. It knows nothing about users, roles,
schedules, or the database — only how to run one scan and hand back results.

| Method & path | Purpose |
|---|---|
| `POST /v1/scans` | Start a scan. Body: `{ targets[], templates:{template_ids[], templates_commit}, options:{rate_limit, concurrency, timeout, discovery:{enabled, scan_type, ports, timeout_sec}} }` → `202 { scan_id }`, runs async. The node resolves ids from the active manifest and rejects missing ids/commit drift before launch. `options.discovery` drives the optional naabu port-discovery pre-pass (#86) |
| `GET /v1/scans/{id}` | Status + progress + stats (`running`/`complete`/`failed`) |
| `GET /v1/scans/{id}/results` | Stream NDJSON results (backend pulls on completion) |
| `POST /v1/scans/{id}/cancel` | Cancel a running scan |
| `POST /v1/templates/bundle` | Receive the **full-catalog** template bundle the backend pushes (#85): a gzipped tar of every active template's YAML + a `manifest.json`. The node holds the whole catalog (a scan selects by id); the backend pushes it on an hourly idle cadence + a pre-dispatch top-up when stale. The node extracts to staging, verifies every file sha256 and canonical `manifest.digest` (`types.BundleDigest`), then activates under an exclusive `TryLock` — refusing (`400`) a bad archive/path/hash/digest and (`409`) a push while any scan holds the active tree. → `{ templates_commit, template_count }`. Strictly backend→node (invariant #2); the node never pulls. |
| `GET /v1/capabilities` | `{ nuclei_version, templates_commit }` — polled by the backend for node liveness (#98); `templates_commit` is the digest of the active bundle (empty until one is pushed), used to detect drift before dispatch |
| `GET /healthz` | Liveness / readiness |

- **Auth:** `Authorization: Bearer <service-token>`, TLS required. **mTLS upgrade (#26):** for a
  node in an untrusted segment, the node serves HTTPS and requires a verified client cert
  (`SCANNER_TLS_CERT`/`SCANNER_TLS_KEY`/`SCANNER_CLIENT_CA` on the scanner process), and the backend
  presents a client cert / pins the node's server CA — configured **per node in the registry**
  (`tls_server_ca`/`tls_client_cert`/`tls_client_key`), not global env, so segments can differ. The
  bearer token still applies on top (additive). In a K8s service mesh the sidecar can terminate mTLS
  instead, leaving these unset.
- **Node registry:** scanner nodes live in a DB-backed registry (`scanner_nodes`) managed by
  the admin via `/api/nodes` (or a service-account script); `SCANNER_URL`/`SCAN_ZONES` only
  **seed** it on first boot. Each node serves a set of CIDRs (a node with none is a catch-all);
  CIDRs are non-overlapping, so a target's IP maps to exactly one node — no load-balancing.
  **Not** self-registration: nodes never call the backend (see the invariant below). The backend
  polls each node's `GET /v1/capabilities` for liveness (#98), and dispatch fails fast to a
  known-unhealthy node.
- **Node initiates nothing toward the backend** — all traffic is backend → node
  (dispatch, poll, pull results). The node's only outbound paths are scan targets and the
  template repo, which keeps a segmented node easy to firewall.

---

## 5. Cloud portability strategy

The whole stack is **containers + Postgres + object storage**, nothing proprietary:

| Environment | Postgres | Object store | Run target |
|---|---|---|---|
| Local / single box | Compose PG | MinIO | `docker compose up` |
| AWS | RDS | S3 | ECS Fargate / EKS |
| GCP | Cloud SQL | GCS | Cloud Run / GKE |
| Azure | Flexible Server | Blob | Container Apps / AKS |

One set of images, one Helm chart (or Compose file). The only per-cloud work is wiring
managed Postgres + a bucket + the IdP — config, not code.

**Trade-off vs. "use native scheduler/queue":** we hand-write a small scheduler + queue
(~1–2 days on Postgres). In exchange we get true multi-cloud portability *and*
byte-identical local development. For a small team that owns the tool, that's the right
trade; the native-services path only wins if you're committed to one cloud forever.

---

## 6. Security (right-sized — not the enterprise maximum)

- **Scanner node holds no DB credentials** — it receives a scan spec and returns
  results, nothing more. A compromised node in a segmented network can't reach the system
  of record. This is the main security payoff of splitting it out.
- **Scope guardrail (most important):** a scan may only target hosts inside an approved
  `target` record. Every scan runs a **scan policy**, and a policy always references a
  stored target, so a scan is in scope **by construction** — there is no path to name a
  host that isn't already an approved target. Prevents fat-fingering a scan at
  out-of-scope / third-party assets, which for a scanner is the difference between a tool
  and an incident.
- **Egress control:** run scanner nodes in a segmented network / per zone; the node makes
  active connections to targets, so treat its egress like an attack surface.
- **BFF token custody:** OIDC access/refresh tokens live server-side in the backend; the
  SPA only ever holds an httpOnly, SameSite session cookie — no tokens in browser JS.
- **Service-token hygiene:** backend→node bearer tokens are per-node secrets, rotatable,
  TLS-only; mTLS is the upgrade when you want mutual auth.
- **Secrets:** target auth creds (if any) never in the DB plaintext or templates —
  behind a secrets interface (env/SOPS local, cloud secret manager in prod).
- **Audit log** — every mutating call is emitted as a structured `event=audit` log line
  to stdout, where the platform's log aggregator ingests/retains/queries it. Off-DB by
  design, so a DB compromise can't rewrite the trail; a small `event_id` vocabulary drives
  detections. Template and template-set imports use `event_id=config_changed`,
  `action=templates.import`; exports are read-only and do not emit mutations.
- **Authz on every mutating endpoint** — the three roles are enforced server-side.
- Patch your own deps: a vuln scanner running on stale libraries is a bad look.

---

## 7. Decisions

**Settled:**
- **Backend:** Go.
- **Frontend:** React + TypeScript + Vite SPA calling the backend API.
- **User auth:** OIDC/SSO via the BFF pattern (Cognito / Entra / Keycloak).
- **Topology:** separate scanner node(s) with their own API, backend-dispatched,
  API-token auth, no DB credentials on the node.

Also settled:
- **Nuclei on the node:** the **binary/CLI**, not the Go SDK. Upgrade = bump the image;
  crash isolation via subprocess; cancel/timeout by killing the process group.
- **Results flow:** **backend polls** the node (`GET /v1/scans/{id}` for status, then
  `GET /v1/scans/{id}/results` on completion). Pull-only keeps the network flow strictly
  backend → node — no inbound path to a segmented node — and makes in-flight scans fully
  recoverable from Postgres after a restart. No callbacks.
- **Node auth:** **per-node bearer token over TLS**, with optional **per-node mTLS** (#26) for a
  node in an untrusted segment — the app presents/pins certs it stores in the registry, or a K8s
  service mesh terminates mTLS transparently (leave the fields unset). No PKI in the app: issuance
  and rotation stay a deployment concern.

Nothing open.

---

## 8. Future directions

The alpha delivers the full scan → lifecycle → triage → export loop with the security
guardrails above, plus CI and container-image releases (see
[Development](DEVELOPMENT.md#continuous-integration--releases)). Earlier we tracked larger
follow-on work as GitHub issues — cloud IaC deploy (#25), an OpenSearch derived index
(#21), scoped disposition rules (#23), and the regulatory tail of SSO federation, SIEM
shipping, CMK/KMS, and change-approval (#24) — and have since closed them: the team has
chosen not to take that work on, so it is not on the roadmap. Open follow-on work lives
in the issue tracker.
