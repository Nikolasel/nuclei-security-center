# Nuclei Security Center — Architecture & Build Plan

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
- **findings** — `id, target_id, template_id, name, severity, matched_at, raw_json,
  first_seen_scan, last_seen_scan, status (open|triaged|false_positive|fixed)`.
  Keyed on `(target_id, template_id, matched_at)` so lifecycle survives across scans.
- **audit_log** — `id, actor, action, entity, before, after, ts`. Written from day one.

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
| Postgres + **OpenSearch as a *derived* index** | The scale answer — add **later** if findings search/volume demands. Postgres stays source of truth; OpenSearch is a search projection synced at ingest. |
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
| `GET /v1/capabilities` | `{ nuclei_version, templates_commit, zone, tags }` for the registry |
| `GET /healthz` | Liveness / readiness |

- **Auth:** `Authorization: Bearer <service-token>`, TLS required. Upgrade path: mTLS.
- **Node registry:** static list of node endpoints + zone in backend config for the MVP;
  self-registration is a later option. Backend load-balances within a zone.
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
- **Audit log from day one** — cheap to add now, painful to backfill.
- **Authz on every mutating endpoint** — the three roles are enforced server-side.
- Patch your own deps: a vuln scanner running on stale libraries is a bad look.

*(If this ever moves into a regulated/ISMS scope, the additive work is SSO federation,
SIEM shipping of the audit log, CMK/KMS, and going through change-approval — bolt-ons to
this design, not a rewrite. That's the Sonnet estimate's real subject.)*

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
- **Node auth:** **per-node bearer token over TLS** for the MVP; adopt **mTLS
  transparently via a K8s service mesh** when a node lands in an untrusted segment. No PKI
  in the app.

Nothing open — see §8 for the build plan.

---

## 8. Phased build plan (1–2 devs, "small team internal" scope)

Status legend: ✅ done · 🔜 next · ⬜ planned. Each phase ends at a demoable state.

| Phase | Focus | Status | Effort |
|---|---|---|---|
| **0** | Core loop (the spine) | ✅ done | ~3–4 days |
| **1** | CRUD + on-demand scans + auth + SPA | ✅ done | ~2–2.5 wks |
| **2** | Scheduling + finding lifecycle | 🔜 in progress | ~1–1.5 wks |
| **3** | Storage + guardrails + RBAC | ⬜ | ~1 wk |
| **4** | Cloud deploy + hardening | ⬜ | ~1–1.5 wks |

**Total ≈ 6–8 focused weeks for one dev** to a solid internal MVP — well under the
13–20 person-weeks in the original estimate, because the regulatory tail is out of scope.
(The React SPA in Phase 1 is the largest single line item; an htmx UI would have been
~a week less, a trade we took deliberately for richer triage interactivity.)

### Phase 0 — Core loop ✅

Proves the whole architecture end-to-end before any product surface is built.

- **Built:** two-service split (backend + credential-less scanner node), shared wire
  types, Postgres schema + embedded migration runner, scanner API (`/v1/scans` +
  status/results/cancel, bearer auth), backend dispatch → poll → pull → ingest loop,
  Docker Compose (postgres + minio + scanner + backend), Dockerfiles.
- **Verified:** `go build/vet/test` clean; scanner API smoke-tested live (auth 401/202,
  run→failed error capture, 404s); JSONL parse structs checked against real Nuclei output.
- **Exit criteria (met in code; full loop pending local Docker):** `POST /scans` runs
  Nuclei against `scanme.sh` and lands findings in Postgres.

### Phase 1 — CRUD + on-demand scans + auth 🔜  (~2–2.5 wks)

The first genuinely usable product slice.

- **Backend:** targets CRUD (with the scope allowlist), template-set CRUD, replace the
  hardcoded default spec with real scan-from-config, scan history endpoints. ✅ *(slice 1)*
- **Auth:** OIDC via the BFF pattern (§6) — backend as confidential client, httpOnly
  session cookie to the SPA. Wire one IdP (Keycloak locally). ✅ *(slice 2)* — roles
  come from the IdP `groups` claim (admin/operator/viewer); server-side sessions +
  single-use PKCE/state/nonce flow (migration 0003); requireAuth/requireRole guards
  (reads→viewer, scans & config writes→operator, deletes→admin); auth-disabled dev
  mode when `OIDC_ISSUER` is unset; compose ships a seeded Keycloak realm.
- **Frontend:** React + TS + Vite SPA — targets/template-sets management, "run scan"
  flow, findings table (server-side severity/host filters + pagination), a per-finding
  **vulnerability detail page** (full parsed Nuclei output: classification/CVE, request/
  response, curl reproducer, references, remediation, raw JSON), and a scan detail view.
  ✅ *(slice 3)* — Tailwind + Radix; TanStack Query; role-gated controls; served
  same-origin as an embedded build (`go:embed`) so the BFF cookie stays same-site; the
  API moved under `/api/*`.
- **Exit criteria (met):** a logged-in user defines a target + template set in the UI,
  runs a scan, and browses the resulting findings.

### Phase 2 — Scheduling + finding lifecycle 🔜  (~1–1.5 wks)

Turns point-in-time scans into a tracked signal. Built in three slices, one PR each.

- **Lifecycle:** ✅ *(slice 1)* — findings split into two tables: `findings` stays the
  immutable per-scan **occurrence** log (raw JSONL preserved), and a new
  `finding_lifecycle` is the **deduplicated** entity keyed on `(target_id, template_id,
  matched_at)` (migration 0005). Ingest inserts an occurrence + upserts the lifecycle row
  (`first_seen`/`last_seen`, denormalised latest display fields); a finding marked `fixed`
  is auto-reopened when re-observed. Triage `status` (open / triaged / false_positive /
  fixed) lives on the lifecycle entity so it survives across scans. **"new since last
  scan"** and **"resolved/gone"** are derived at read time (vs. the target's latest
  completed scan) so they never go stale. API: `GET /api/findings` (dedup view, with
  `status`/`view` filters), `GET /api/scans/{id}/findings` (occurrences),
  `PATCH /api/findings/{id}/status` (operator). SPA: view tabs (All/Open/New/Resolved),
  status filter, and a triage panel on the detail page.
- **Scheduling:** ⬜ *(slice 2)* — cron schedules in the backend ticker → dispatch (the
  `schedules` table from §3), enable/disable in the UI.
- **Exports:** ⬜ *(slice 3)* — JSON / SARIF / CSV (Nuclei emits the first two natively).
- **Exit criteria:** a nightly schedule runs unattended; the UI shows what's new vs.
  resolved between runs and lets a user triage a finding.

### Phase 3 — Storage + guardrails + RBAC ⬜  (~1 wk)

Hardening and the security guardrails from §6.

- **Object storage:** wire the S3-compatible interface (MinIO already in Compose) to
  archive raw `out.jsonl`/SARIF per scan.
- **RBAC:** enforce the three roles (admin / operator / viewer) on every mutating endpoint.
- **Audit log:** surface the `audit_log` (written since Phase 1) in the UI.
- **Scope guardrail:** hard-enforce that a scan can only target hosts inside an approved
  target record; per-zone scanner selection.
- **Exit criteria:** raw output is archived and downloadable; roles are enforced; an
  out-of-scope target is rejected before dispatch.

### Phase 4 — Cloud deploy + hardening ⬜  (~1–1.5 wks)

- **Deploy:** Helm chart (or Terraform) for the chosen cloud — managed Postgres + bucket +
  IdP wiring; scanner nodes deployable per network zone.
- **Service auth upgrade:** turn on mTLS via the service mesh where nodes sit in untrusted
  segments (§7).
- **Hardening + UAT:** dependency scan of our own stack, egress controls on scanner nodes,
  bug-fix buffer.
- **Exit criteria:** the stack runs on the target cloud from IaC, with segmented scanner
  nodes and a passing hardening review.

### Beyond MVP (deferred, not scheduled)

- **OpenSearch** as a derived findings index if search/volume outgrows Postgres (§3a).
- **Scanner node registry** with self-registration (vs. the static config list).
- **Regulatory tail** (only if scope changes): SSO federation, SIEM shipping of the audit
  log, CMK/KMS, change-approval — additive to this design, not a rewrite.
