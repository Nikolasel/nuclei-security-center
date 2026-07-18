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
   │  scheduler + dispatch     │ ◀──────│  sync templates ─▶ run nuclei ─▶   │
   │  RBAC + audit log         │ results│  serve JSONL results (pull-only)   │
   └────────────┬──────────────┘        └───────────────────┬────────────────┘
                ▼                                            ▼
        Postgres + S3-compatible store          private git template repo
        (system of record + raw output)         (pinned ref per template set)
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
| Templates | Private git repo, pinned ref | Scanner `git pull` before runs; version recorded per scan for reproducibility |
| User auth | OIDC via BFF (Cognito / Entra / Keycloak) | SSO everywhere; tokens stay server-side, SPA gets only a session cookie |
| Service auth | API bearer token (TLS); mTLS as upgrade | Backend → scanner-node calls, no user identity involved |

---

## 3. Data model (core tables)

- **users** — `id, email, role` where role ∈ `admin | operator | viewer`.
- **targets** — `id, name, hosts[] (CIDRs/URLs), tags[], created_by`. Targets are the
  **scope allowlist** — scans can only hit pre-approved hosts (guardrail, see §6).
- **template_sets** — `id, name, git_ref, filter (severities[], tags[], paths[])`.
- **schedules** — `id, target_id, template_set_id, cron, rate_limit, concurrency, enabled`.
- **scans** — `id, source (schedule|adhoc), status, started_at, finished_at,
  nuclei_version, templates_commit, triggered_by`.
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
2. **Dispatch** — the backend picks a scanner node for the target's zone and calls
   `POST /v1/scans` with the spec (targets, template ref + filters, rate/concurrency/
   timeout). On `202` it records the node's `scan_id` and marks the scan `dispatched`.
   If no node is reachable, it stays `queued` and retries with backoff.
3. **Prepare (on node)** — the node `git pull`s templates to the set's pinned ref and
   reports back `nuclei_version` + `templates_commit` (reproducibility + audit).
4. **Run (on node)** — `nuclei -l targets.txt -t <paths> -jsonl -o out.jsonl` plus the
   rate-limit / concurrency / timeout flags from the spec.
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
| `POST /v1/scans` | Start a scan. Body: `{ targets[], templates:{git_ref, filters}, options:{rate_limit, concurrency, timeout} }` → `202 { scan_id }`, runs async |
| `GET /v1/scans/{id}` | Status + progress + stats (`running`/`complete`/`failed`) |
| `GET /v1/scans/{id}/results` | Stream NDJSON results (backend pulls on completion) |
| `POST /v1/scans/{id}/cancel` | Cancel a running scan |
| `POST /v1/templates/sync` | Force a template ref sync (also done inline before each scan) |
| `GET /v1/capabilities` | `{ nuclei_version, templates_commit }` — polled by the backend for node liveness (#98) |
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
  `target` record. Prevents fat-fingering a scan at out-of-scope / third-party assets —
  which for a scanner is the difference between a tool and an incident.
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
  detections.
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
