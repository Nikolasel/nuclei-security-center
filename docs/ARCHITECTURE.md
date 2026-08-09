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
| Templates | Lossless Postgres catalog → pushed node bundle | Backend owns upstream/custom content; scans select ids from a content-addressed full-catalog bundle. Custom writes are accepted only after a healthy node's pinned Nuclei validates the YAML |
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
  upstream commit, resulting canonical `templates_commit` + template count, and
  added/updated/removed/skipped counts. Failed runs record the unchanged active bundle state, so a
  node reporting an older digest can be matched to catalog history (a stray malformed file is
  skipped-and-counted, not fatal; the run fails closed only if nothing parses). Runs are retained
  in PostgreSQL and exposed through a paginated history; NSC does not silently prune them.
- **template_sets** — an explicit `mode`: `exact` uses curated membership in
  `template_set_members`, `all` resolves every active catalog template at scan time, and `exclude`
  resolves every active template except explicit rows in `template_set_exclusions`. The retired POC
  filter columns and compatibility code are not part of the beta schema. Exact sets and selected
  templates are portable as either a lossless YAML tarball (verbatim files + manifest) or one JSON
  document retaining the verbatim YAML strings; catalog-derived sets export their mode and
  exclusions rather than freezing the current catalog. Import writes custom templates, set
  membership, and exclusions atomically; upstream rows remain sync-owned and are reference-only.
  The exclusion foreign key is restrictive: a custom template referenced by an exclude-set
  exclusion must be consciously removed from that deny-list before it can be deleted.
- **scan_policies** — `id, name, template_set_id, rate_limit, concurrency, timeout_sec,
  max_host_error, discovery_*`. The central, reusable **how to scan** configuration: a required
  template set (exact, all, or exclude) plus Nuclei/discovery knobs (each nullable = "use the
  built-in default"). Every scan and schedule selects a policy and an approved target
  independently, so one policy can be reused across scopes. A template set referenced by a policy
  cannot be deleted.
- **schedules** — `id, scan_policy_id, target_id, cron, enabled` — a policy and approved target
  paired with a cadence. Deleting either referenced row cascades the schedule away.
- **scans** — `id, source (schedule|adhoc), scan_policy_id, target_id, template_set_id, status,
  started_at, finished_at, nuclei_version, templates_commit, skipped_finding_count, triggered_by`.
  The selected target and policy's template set are resolved and recorded on the scan at dispatch
  (so findings keep working and history survives `scan_policy_id` being nulled on policy delete —
  `ON DELETE SET NULL`). `skipped_finding_count` records only source records proven malformed
  during backend ingest; database, transaction, schema, and unexpected constraint failures remain
  scan-fatal.

- **findings** (occurrences) — the immutable per-scan observation log: `id, scan_id,
  target_id, finding_id, dedup_key, result_discriminator, template_id, name, severity,
  host, matched_at, raw_line, raw`.
  `raw_line` preserves valid Nuclei JSONL text (invalid UTF-8 becomes U+FFFD; the object
  archive remains byte-exact); `raw` is a NUL-safe JSONB projection retained for ad-hoc
  operator SQL because affected source lines cannot be cast to JSONB. Historical rows may
  leave `raw_line` NULL and readers fall back to `raw::text`, avoiding a blocking backfill.
  Answers "what did scan X observe"; feeds the raw archive in object storage.
- **finding_lifecycle** — the **deduplicated, triageable** entity keyed on
  `(template_id, matched_at, stable result discriminator)` **globally across scans and
  target records**. Scan/target are occurrence provenance, not identity. The discriminator
  hashes only stable result dimensions (`matcher-name`, `extractor-name`, and sorted
  `extracted-results`); volatile timestamps/request/response bytes never fragment lifecycle
  continuity. Occurrence `target_id` is a denormalized copy retained for indexed lifecycle
  projection/filtering; targeted occurrences are constrained to their owning scan's scope,
  while coverage logic uses `scans.target_id` as its authority. This lets a multi-result template keep, for example, TLS 1.2 and TLS 1.3 as
  distinct entities even when both share one endpoint. Extracted values remain part of the
  fallback identity because Nuclei templates can emit distinct results without matcher or
  extractor names; a template that extracts volatile values therefore intentionally produces
  distinct lifecycle entities and should be authored with a stable discriminator when continuity
  is wanted. Models a
  **Tenable Security Center-style** two-dimensional lifecycle:
  - *Detection state* — **derived at read time** from scan observation, never stored:
    **New / Active / Resurfaced** (cumulative — still detected) and **Mitigated /
    Previously Mitigated** (no longer detected). The comparison scan is the latest
    completed scan, across target/ad-hoc scopes that have previously observed this global
    result, whose persisted concrete `template_ids` includes the finding's template **and**
    whose Nuclei request trace proves that the same template completed a successful request
    against the finding's normalized `matched_at` host:port. A narrower scan that omitted the
    template, reached only another service on the host, or had Nuclei abandon the host before
    this template ran is not evidence of mitigation.
    Legacy scans with an occurrence prove positive coverage, while an absence without
    concrete ids proves nothing and fails closed. The latest covering scan's id is
    materialized on each lifecycle row when a scan completes (and rebuilt after scan
    deletion); this is an evidence pointer, not a stored detection state, and keeps
    lifecycle reads independent of scan-history/template-array size. `times_mitigated`
    (maintained at ingest with the same coverage rule) distinguishes a first
    disappearance from a flapping one. **Closure is evidence-driven — there is no
    manual "fixed."** `scans.covered_endpoints` stores the deduplicated
    `{template_id, endpoint}` positive trace evidence: NULL means unavailable and fails
    closed, while an empty array is known zero coverage. `scans.coverage_origin` durably records
    whether that column came from a local node trace, an ordinary untrusted import, or the
    explicit trusted-import mode; lifecycle repair accepts claimed coverage only from the local
    node or trusted-import origins. The operator's trusted-import choice is also emitted in the
    audit event, because an operator-role compromise remains able to assert that mode by design.
    Endpoint normalization uses
    scheme defaults and Nuclei's `type` (`http`→80, `https`/TLS→443, DNS→53,
    WHOIS→43). Findings such as `file`/`code` results that have no network host:port
    deliberately remain ineligible for automatic mitigation; the API/UI exposes this as
    `auto_mitigation_eligible=false` rather than silently implying they can close.
    Exact occurrences always remain positive evidence for their own lifecycle entity.
  - *Disposition* — the analyst overlay (the only manual state): **Accept Risk** (with an
    optional `accept_expires_at` — an expired acceptance falls back to its detection
    state) and **False Positive**, plus **Recast Risk** (a `recast_severity` override).
    Each carries a note/actor/timestamp audit trio. Migration from the former target-scoped
    identity resolves collisions by taking the most recent disposition action and most
    recent recast action independently, including an explicit clear.
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
2. **Resolve + top up** — the backend resolves the policy's required template set to concrete
   catalog ids (an exact snapshot, every active id, or every active id except
   `template_set_exclusions`), computes the full active
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
   A scan policy can pick the port-scan mode per-scan (`discovery_scan_type` = `syn`|`connect`);
   unset, it uses the node's `NAABU_SCAN_TYPE` default. Host discovery is an independent nullable
   policy setting (`discovery_host_discovery`): unset preserves today's mode default (on for SYN,
   off for connect), while true runs the two-pass host-discovery flow for either mode and false runs
   one port-scan pass for either mode. Connect is an unprivileged TCP connect scan and, with its
   default host-discovery setting, scans every host without the extra pruning pass — no capabilities
   or libpcap, but slower — for deployments that drop `NET_RAW`; requesting `syn` on such a node fails
   the scan closed. Note connect still narrows Nuclei to the open ports it finds when discovery is enabled;
   it only loses the dead-host pruning by default. An explicitly enabled host-discovery pass uses the
   same SYN/raw-socket probes even when the port-scan mode is connect. Discovery has
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
   persisted `discovered_targets`; see [Development](DEVELOPMENT.md#docker-desktop-discovery-caveat)).
4. **Run (on node)** — `nuclei -l targets.txt -t <paths> -jsonl -o out.jsonl` plus the
   rate-limit / concurrency / timeout flags from the spec. When discovery ran,
   `targets.txt` is the narrowed `host:port` list from step 3a. Nuclei also writes its
   structured `-trace-log` into a private FIFO and reduces it while Nuclei runs, avoiding an
   unbounded trace file on node disk. A read/write anchor installs the reader before process
   launch and guarantees EOF even if Nuclei never opens the trace; a bounded post-process wait
   fails closed rather than wedging the scan. Successful (`error = "none"`) requests become exact
   `{template_id, endpoint(host:port)}` pairs returned as `covered_endpoints`; connection
   errors do not count, so another port or a template skipped by `max-host-error` cannot make
   an absent finding look mitigated. Malformed or unmapped records are skipped and surfaced
   as `coverage_warning`; an unreadable trace or the bounded pair limit fails closed.
5. **Poll for results** — the backend polls `GET /v1/scans/{id}` for status/progress,
   then pulls `GET /v1/scans/{id}/results` (NDJSON stream) once the node reports
   `complete`. Pull-only: the flow is strictly backend → node, and in-flight scans resume
   from Postgres if the backend restarts. No node → backend inbound path exists.
6. **Ingest (on backend)** — the backend parses the JSONL, inserts immutable occurrence
   rows, and upserts global lifecycle rows, updating first/last-seen evidence. A malformed source
   record may be skipped and counted when its failure is proven record-local; database, transaction,
   schema, and unexpected constraint failures abort the scan instead of producing silently partial
   results. A completed scan with skipped records cannot provide negative mitigation evidence, while
   exact occurrences it did ingest remain positive evidence. **All dedup/lifecycle lives here** —
   the node stays stateless.
7. **Persist** — store `covered_endpoints` and any `coverage_warning`, upload raw `out.jsonl`
   (+ optional SARIF) to object storage, then atomically mark the scan complete. Completion
   expands coverage JSON once and joins it through the indexed lifecycle
   `(template_id, endpoint_key)` pair before advancing matching evidence pointers; write audit
   entries.
8. **Failure path** — node timeout/non-zero exit, or dispatch/poll failure → status
   `failed`, capture stderr tail and the reason.
9. **Bundle export / import (#136)** — a viewer-level `GET /api/scans/{id}/export`
   serializes the **complete record of one scan result** into a versioned,
   self-contained manifest (`format` + `format_version`, `scan` record incl.
   timestamps/state/source/`discovered_targets`/`covered_endpoints`/`coverage_warning`/resolved
   `template_ids` + `templates_commit`/verbatim `spec`, config refs + snapshots,
   and all **occurrences** with their preserved raw JSONL). Like a scan-results
   file (a Nessus `.ness` import), the bundle carries **the scan's data, not the
   exporter's globally deduplicated finding lifecycle** — analyst
   overlays/first-last-seen/mitigation counters are never exported. The same
   document ships as `manifest.json` in a zip. An operator-level, audited
   `POST /api/scans/import` recreates the scan on the destination **in one
   transaction** and ingests its findings through the same lifecycle path a
   completed scan uses: the dedup identity is recomputed from the verbatim raw
   payload (never trusted from the manifest), and the destination **re-derives
   its own lifecycle** (detection state, first/last-seen, mitigation counters,
   overlays) from the results exactly as if it had scanned the target itself.
   `covered_endpoints` and `coverage_warning` remain in the portable export
   format for provenance, but are untrusted exporter-authored claims. The default
   import mode (`coverage=ignore`) discards them and stores coverage as NULL;
   an explicit operator opt-in (`coverage=trust`) persists exact endpoint pairs
   and may use them for mitigation under the same scope/skipped-record rules as a
   local completed scan. Exact occurrences carried by the bundle always provide
   positive lifecycle evidence.
   `discovered_targets` is retained as display-only provenance and is not coverage
   evidence; lifecycle logic must not use it for mitigation.
   Missing local references (target / template set / scan policy / node /
   schedule) fall back to NULL and are reported — never a failure. In-flight
   exports import as `failed`; a scan id that already exists locally is `409` by
   default (`conflict=duplicate` mints a fresh id). Import is fail-soft on
   references but fail-hard on the manifest itself: version-checked, validated,
   bounded (`ScanBundleMaxFindings` occurrences, 512 MiB upload cap,
   zip-bomb-limited extraction).

---

## 4a. Scanner node API (service-to-service, Bearer token over TLS)

The node is a small, self-contained HTTP service. It knows nothing about users, roles,
schedules, or the database — only how to run one scan and hand back results.

| Method & path | Purpose |
|---|---|
| `POST /v1/scans` | Start a scan. Body: `{ targets[], templates:{template_ids[], templates_commit}, options:{rate_limit, concurrency, timeout, discovery:{enabled, scan_type, ports, timeout_sec}} }` → `202 { scan_id }`, runs async. The node resolves ids from the active manifest and rejects missing ids/commit drift before launch. `options.discovery` drives the optional naabu port-discovery pre-pass (#86) |
| `GET /v1/scans/{id}` | Status + progress + stats (`running`/`complete`/`failed`) plus terminal `covered_endpoints` request-trace evidence and an optional `coverage_warning` |
| `GET /v1/scans/{id}/results` | Stream NDJSON results (backend pulls on completion) |
| `POST /v1/scans/{id}/cancel` | Cancel a running scan |
| `POST /v1/templates/bundle` | Receive the **full-catalog** template bundle the backend pushes (#85): a gzipped tar of every active template's YAML + a `manifest.json`. The node holds the whole catalog (a scan selects by id); the backend pushes it on an hourly idle cadence + a pre-dispatch top-up when stale. The node extracts to staging, verifies every file sha256 and canonical `manifest.digest` (`types.BundleDigest`), then activates under an exclusive `TryLock` — refusing (`400`) a bad archive/path/hash/digest and (`409`) a push while any scan holds the active tree. → `{ templates_commit, template_count }`. Strictly backend→node (invariant #2); the node never pulls. |
| `POST /v1/templates/validate` | Validate one raw-YAML custom template with the node's pinned `nuclei -validate`, without a target. The body is limited to 1 MiB and executed in a private temporary directory with a 30-second deadline and bounded diagnostics. Returns `{ valid, errors[], nuclei_version }`; a rejected template is a `200` verdict (`valid=false`), while execution/timeout faults use 5xx. Backend custom create/update calls this only on a node already known healthy and fails closed if none is available. |
| `POST /v1/templates/validate-batch` | Validate a transient catalog-format bundle in **one** pinned `nuclei -validate` process (#140). The node verifies the manifest/hashes, extracts under its private work root, returns bounded global + per-manifest-ID diagnostics and `nuclei_version`, then removes the tree without activating it. Backend archive import sends only the final custom create/overwrite/renamed writes selected by conflict policy; invalid/unavailable validation prevents the atomic store transaction. |
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
  `target` record. Every scan selects a **scan policy** and stored **target**, so it is in
  scope **by construction** — there is no path to name a host that isn't already an approved
  target. Prevents fat-fingering a scan at
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
- **Audit log** — every mutating call and rejected authentication attempt is emitted as a structured
  `event=audit` log line
  to stdout, where the platform's log aggregator ingests/retains/queries it. Off-DB by
  design, so a DB compromise can't rewrite the trail; a small `event_id` vocabulary drives
  detections. Successful ad-hoc, manual-schedule, and cron dispatch events include the resolved
  policy, target, and scan IDs, so the selected scope is not recorded only in the mutable app
  database; unattended cron dispatches use `actor_type=system`. Template and template-set imports
  use `event_id=config_changed`, `action=templates.import`; exports are read-only and do not emit
  mutations.
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

The beta delivers the full scan → lifecycle → triage → export loop with the security
guardrails above, plus CI and container-image releases (see
[Development](DEVELOPMENT.md#continuous-integration-and-releases)). Earlier we tracked larger
follow-on work as GitHub issues — cloud IaC deploy (#25), an OpenSearch derived index
(#21), scoped disposition rules (#23), and the regulatory tail of SSO federation, SIEM
shipping, CMK/KMS, and change-approval (#24) — and have since closed them: the team has
chosen not to take that work on, so it is not on the roadmap. Open follow-on work lives
in the issue tracker.
