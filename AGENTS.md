# AGENTS.md

Guidance for agentic runs in this repo. Keep it current when structure or conventions change.

## What this is

`nuclei-security-center` — a web interface for running and triaging [Nuclei](https://github.com/projectdiscovery/nuclei)
scans, for a small internal security/eng team, built cloud-portable.
Repo: `git@github.com:Nikolasel/nuclei-security-center.git`.

**`docs/ARCHITECTURE.md` is the source of truth for design decisions.** Read it before making
architectural changes. `README.md` is the visitor-facing overview; the practical guides live
under `docs/` (`ADMIN_GUIDE.md`, `API.md`, `DEVELOPMENT.md`).

The product is a working beta: a logged-in user manages targets/template-sets, runs scans
(on demand or on a cron **schedule**), and triages a **Tenable-style finding lifecycle** (dedup +
first/last-seen + detection state + dispositions/recast), exporting the lifecycle list as
JSON/CSV/SARIF/raw. OIDC/BFF auth with IdP-driven roles fronts a React SPA. Cross-cutting: a
structured **audit log**, per-scan **raw-output archival** to object storage, **RBAC** on every
mutating endpoint, and a **scope guardrail** keeping scans inside approved targets. CI +
container-image releases run on GitHub Actions (`.github/workflows/`). Future work is tracked as
GitHub issues (see §8 of the architecture doc).

**Scope guardrail (§6 — the most important guardrail):** a scan may only target
hosts inside an approved `target` record. Every scan is launched from a **scan policy**
and an approved target (`POST /api/scans` takes `scan_policy_id` + `target_id`), so a scan is
**in scope by construction** — there is no ad-hoc host/spec path to name an out-of-scope host.
Target hosts are validated (hostname/IP/CIDR/URL, host-granular, DNS-free) when a target is
created. **Fails closed:** no approved targets ⇒ no scan.
(`internal/backend/scope.go`'s `outOfScopeHosts`/`AllTargetHosts` remain as the allowlist
primitives, retained for reuse though the removed ad-hoc `spec` path was their only caller.)

**Object storage:** the verbatim Nuclei `out.jsonl` is archived per scan to an
S3-compatible bucket (MinIO locally; any S3 API in the cloud) via `github.com/minio/minio-go/v7`
behind a small `ObjectStore` interface (`internal/backend/objectstore.go`, Put/Get; a fake
in tests). The orchestrator **tees** the results stream to a temp file during ingest and
uploads `scans/<id>/raw.jsonl` afterward — **best-effort**: Postgres stays the system of
record, so an upload failure logs but never fails the scan. `scans.raw_object_key` stores the
key; the API exposes only `has_raw`. `GET /api/scans/{id}/raw` (viewer)
streams the archive back **through the BFF** (same-origin cookie — no presigned URLs). Config
is `S3_ENDPOINT`/`S3_BUCKET`/`S3_ACCESS_KEY_ID`/`S3_SECRET_ACCESS_KEY`/`S3_USE_SSL`/`S3_REGION`;
unset `S3_ENDPOINT` ⇒ archiving disabled (dev). Authentication remains fail-closed unless
`AUTH_DISABLED=true` is explicitly set.

**Audit log:** every mutating API call and rejected authentication attempt emits one structured
`slog` event (`event=audit`) to **stdout** — no DB table, no in-app UI. The trail lives in the
platform's log aggregator (CloudWatch / Log Analytics / Cloud Logging / Loki), which owns
retention + querying; keeping it off the app DB means a DB compromise can't rewrite it.
`internal/backend/audit.go` wraps every mutating route with
`s.mutation(eventID, action, objectType, role, h)` (replacing bare `requireRole`): it runs authz
then logs actor / `event_id` / `action` / object type+id / method / path / status / duration.
`event_id` is a small fixed vocabulary for detections — `access_denied` (authentication rejected,
HTTP 401, or an audited mutation rejected by authorization, HTTP 403), `config_changed`
(targets/template-sets/schedules CUD, or scan-history deletion), `scan_dispatched` (scan submit or schedule run),
`finding_triaged` (disposition/recast), `service_account_changed`
(API-token create/rotate/revoke) — all at INFO (a denial is normal enforcement, not a fault).
Authenticated events carry `actor_type` (`user` or `service_account`) so headless token callers
are never conflated with people; rejected authentication events use `actor_type=unknown` and a
non-secret `auth_method` classification.
Successful dispatch actions (`scan.create`, manual `schedule.run`, and cron dispatch) additionally
carry the resolved `scan_policy_id`, `target_id`, and `scan_id`, keeping the selected scope in the
off-DB trail; unattended cron dispatches use `actor_type=system`.

**Scan policies (#87 — the central scan config):** `scan_policies` is the reusable, named **how to scan**
configuration and is required for every launch. It bundles `template_set_id` (required, FK
`ON DELETE RESTRICT`; a set is `exact`, `all`, or `exclude`) and Nuclei's
execution knobs `rate_limit` / `concurrency` / `timeout_sec` / `max_host_error` (each column
nullable = "use the built-in default"). `POST /api/scans` takes
`{scan_policy_id,target_id}`; `Server.resolvePolicySpec` loads the policy and resolves the
request's approved target plus the policy's template set via `resolveConfigSpec`, then overlays
the policy's non-nil knobs over `defaultOptions()` (pure step: `overlayScanPolicy`). The
resolved `target_id`/`template_set_id`
are recorded on the scan (via `ScanLink`) so findings/lifecycle work unchanged; `scan_policy_id`
on `scans` is `ON DELETE SET NULL` (history survives a policy delete). `max_host_error` wires
Nuclei's `-max-host-error` into `buildArgs` (`<= 0` omits the flag, so Nuclei's own default of 30
applies) — the fix for fragile devices Nuclei would otherwise abandon mid-scan, silently skipping
their not-yet-run executors. CRUD at `GET/POST /api/scan-policies`,
`GET/PUT/DELETE /api/scan-policies/{id}` (viewer/operator/operator/admin, audited
`config_changed`, action `scan_policy.*`). `internal/backend/crud.go` +
`internal/store/scanpolicies.go`.

**Template catalog (#85):** Postgres owns the lossless YAML catalog (`templates`) and template
sets. Exact sets use `template_set_members`; `all` sets resolve every active catalog template at
dispatch; `exclude` sets resolve every active catalog template minus explicit exclusions. The retired
POC filter columns and compatibility code are not part of the beta schema. Scans carry concrete
`template_ids` plus the full-catalog `templates_commit`.
The backend pushes that full catalog to nodes; nodes select IDs from their verified active bundle
and reject missing IDs or digest drift. Viewer exports and operator imports round-trip selected
templates or an explicit set as a YAML tarball / JSON portability document; custom YAML remains
lossless, upstream entries stay sync-owned, and imports apply conflict policy plus set membership in
one transaction. `internal/backend/template_syncer.go`,
`internal/backend/distributor.go`, `internal/store/templates*.go`, and
`internal/scanner/bundle.go`. Custom template create/update is additionally fail-closed behind
authoritative validation by a known-healthy scanner node: authenticated
`POST /v1/templates/validate` runs the pinned `nuclei -validate` with no target, a bounded body /
timeout / diagnostic response, and reports the Nuclei version; invalid YAML maps to backend `400`,
while no healthy validator or a node execution/transport failure maps to `503`. Portability imports
apply conflict policy first, package only the final custom create/overwrite/renamed writes into a
transient verified bundle, and call `POST /v1/templates/validate-batch`: one bounded Nuclei process,
per-template diagnostics, and no store transaction unless the entire selected batch is valid (#140).

**Port discovery (#86 — naabu pre-pass):** a scan policy can drive an optional
**naabu** port scan on the scanner node *before* Nuclei, so Nuclei only probes live
`host:port` pairs instead of every address in a CIDR-scoped target (the motivating
win: a `/24` is 256 hosts Nuclei would otherwise probe for every template). Policy columns include
`discovery_enabled` (**default TRUE** — on unless disabled),
`discovery_ports` (naabu `-port` spec, NULL = top-1000), `discovery_timeout_sec`
(discovery's **own** budget, separate from the Nuclei `timeout_sec`), plus naabu
per-probe tuning `discovery_rate`/`discovery_probe_timeout_ms`/`discovery_retries`
(each NULL = naabu's default; lower = faster but can miss slow/lossy ports), plus
`discovery_scan_type` (`syn`|`connect`, CHECK-constrained, NULL = the node's
`NAABU_SCAN_TYPE` default). These flow into
`ScanSpec.Options.Discovery` via `overlayScanPolicy`. The stage lives **entirely on the
node** (`internal/scanner/discover.go`): `Runner.run` writes `targets.txt`, runs naabu,
parses the live `host:port`s, and feeds the narrowed list to Nuclei. **Scan mode
(policy `discovery_scan_type`, else node `NAABU_SCAN_TYPE`, default `syn`):** SYN scan + host discovery (`-with-host-discovery`,
probing ICMP echo **and** TCP SYN/ACK to 80/443 so ICMP-blocked-but-web-open hosts are
still found alive) — host discovery prunes dead hosts, the big speed win on sparse ranges.
This needs raw sockets (`CAP_NET_RAW`, in Docker's default caps) + **libpcap** (the runtime
image stays hardened `ubi10-micro`; a `ubi10-minimal` builder stage `microdnf install`s
libpcap and stages its shared-lib closure — libpcap + libibverbs + libnl + libgcc_s — which
the micro image copies in verbatim). `NAABU_SCAN_TYPE=connect` is the unprivileged fallback
(`-scan-type connect -skip-host-discovery`, no libpcap/caps needed, slower — scans every
host). It **fails
closed** — any naabu error/timeout fails the scan (an operator disables discovery on the
policy rather than silently scanning unfiltered); a clean run with zero open ports
completes with no findings. naabu is a **binary we drive** (invariant #3): pinned +
checksum-verified in `deploy/Dockerfile.scanner` (`NAABU_VERSION`), path via `NAABU_PATH`.
naabu's stderr joins Nuclei's in the execution-log archive (#94). **SYN discovery runs as
TWO naabu passes** (`discover.go`): a host-discovery pass (`-sn`, streams alive host IPs to
stdout) then a port-scan of only the alive hosts (`-skip-host-discovery`). The split is
deliberate — naabu only prints its `Found alive host` lines in `-sn` mode, so pass 1 gives a
LIVE host count (a single combined scan reports nothing until it finishes); same total work,
since pass 2 skips the host discovery pass 1 already did. Connect mode is a single port-scan
pass. The node reports a live `ScanStatus.Progress.Phase` (`discovering`/`scanning`); the
discovering phase has no clean percentage (naabu exposes no usable stats feed), so the UI
shows an animated bar plus a tally parsed from naabu's own log (`discoveryWriter` → shared
`discoveryTally`): host count from `Found alive host` (streams live), open-port count from
`Found N ports on host` (arrives per-host at the end of the port scan). The narrowed
host:port list is reported as
`ScanStatus.DiscoveredTargets`, cached live by the orchestrator during the scanning phase and
persisted to `scans.discovered_targets` (`TEXT[]`) at completion, so the scan
detail can show which endpoints were actually scanned.
Nuclei also runs with `-trace-log` into a FIFO and the node reduces error-free request records
to exact `{template_id, endpoint(host:port)}` pairs (`ScanStatus.CoveredEndpoints`). The backend
persists that evidence to `scans.covered_endpoints` (NULL = unknown/fail closed,
empty = known zero) plus an optional surfaced `coverage_warning`. Lifecycle mitigation requires
an exact pair for the finding's `endpoint_key`; another port or a template skipped by
`max-host-error` proves nothing. Scheme/type defaults normalize HTTP→80, HTTPS/TLS→443, DNS→53,
and WHOIS→43; non-network findings expose `auto_mitigation_eligible=false` and never auto-close.
Completion expands the JSON pairs once and uses the `(template_id, endpoint_key)` index. An exact
occurrence remains positive evidence for itself.

**Scheduling:** `schedules` pairs a
`scan_policy_id` (required, FK `ON DELETE CASCADE`) and `target_id` (required, FK
`ON DELETE CASCADE`) with a `cron` expression — the policy supplies templates/knobs and the
schedule supplies the approved target plus cadence. A backend
`Scheduler` ticker (`internal/backend/scheduler.go`, wakes each minute) selects rows where
`enabled AND next_run_at <= now()`, dispatches each via `orch.Submit` (resolving the policy with
the same `resolvePolicySpec`) with `ScanLink{Source:"schedule", ScheduleID:…}`, and advances
`next_run_at`. **Postgres is the source of truth** (survives restart / persists enable-disable);
`github.com/robfig/cron/v3` is used *only* to parse cron and compute the next fire time — no cron
logic in SQL or long-lived in-memory schedulers. Endpoints: `GET/POST /api/schedules`,
`GET/PUT/DELETE /api/schedules/{id}` (viewer/operator/operator/admin),
`POST /api/schedules/{id}/run` (operator, off-cycle dispatch, leaves cadence untouched).

**Findings are two tables:** `findings` is the immutable per-scan
**occurrence** log (holds source JSONL in nullable `raw_line`, normalizing invalid UTF-8
because PostgreSQL TEXT requires valid UTF-8, plus a NUL-safe JSONB projection in `raw` for
ad-hoc operator SQL; readers fall back to `raw::text` for historical rows; the object archive
remains byte-exact; answers "what did scan X observe");
`finding_lifecycle` is the **globally deduplicated** entity keyed on `(template_id,
matched_at, stable result discriminator)` that users triage. The discriminator hashes stable
`matcher-name` / `extractor-name` / canonicalized `extracted-results`, not volatile timestamps
or request/response bytes. Scan and target are occurrence provenance, not lifecycle identity;
the same concrete result merges across target records, while distinct results from one template
and endpoint remain separate. `findings.target_id` is a denormalized copy used for indexed
projection/filtering; a composite FK constrains non-NULL scope to the owning scan, and coverage
logic treats `scans.target_id` as authoritative. Ingest inserts an occurrence and upserts the lifecycle row
(`store.IngestFinding`). The lifecycle follows **Tenable Security Center's model**, two dimensions:

- **Detection state** — derived at read time (vs. the latest completed scan, across scopes
  that have observed the global result, whose concrete `template_ids` includes the finding's
  template) plus a stored `times_mitigated`
  counter, never a stored state: `new` / `active` / `resurfaced` (still detected) and
  `mitigated` / `previously_mitigated` (gone). A narrower scan that omitted the template is
  not mitigation evidence; legacy occurrences prove positive coverage while an absence
  without concrete ids fails closed. `finding_lifecycle.last_covering_scan` materializes the
  latest covering scan's id at scan completion (and is rebuilt after scan deletion); it is an
  evidence pointer, not a stored state, and avoids scanning JSONB history on lifecycle reads.
  **Closure is evidence-driven; there is no manual "fixed."** `times_mitigated` is bumped at
  ingest when a finding reappears after being absent from the previous scan that covered its
  template and successfully reached its normalized host. Request-trace telemetry is fail-closed:
  legacy/unparseable coverage cannot mitigate an absent finding.
- **Disposition** (manual overlay, the only stored state): `none` / `false_positive` /
  `accepted` (Accept Risk; `accept_expires_at` optional — an expired acceptance falls back
  to the detection state) + `recast_severity` (Recast Risk). `effective_state` /
  `effective_severity` overlay disposition on detection.

`GET /api/findings` = lifecycle view (`state`/`disposition`/severity/… filters);
`GET /api/scans/{id}/findings` = occurrences; `GET /api/occurrences/{id}` = one exact immutable
occurrence (the scan UI opens this, never the merged latest result);
`PATCH /api/findings/{id}/disposition` and
`PATCH /api/findings/{id}/severity` = analyst overlays (operator);
`GET /api/findings/export?format=json|csv|sarif|raw` = the lifecycle list exported in the same
filters (SARIF is a hand-built 2.1.0 doc via `encoding/json`; `raw` emits the preserved Nuclei
JSONL of each finding's latest occurrence — Nuclei's native `out.jsonl`; see `internal/backend/export.go`).
All four formats carry the lifecycle finding `id` as a shared join key (CSV column, JSON `id`,
SARIF `properties.nsc_lifecycle_id`, raw `_nsc_lifecycle_id`) so raw joins back to the projected data.
Workflow dispositions (investigating / in-progress) are intentionally deferred (tracked as a GitHub issue).

The JSON API is served under **`/api/*`**; the React SPA (in `web/`) is built by Vite and
**embedded into the backend binary** (`go:embed`), served at `/` same-origin so the BFF
session cookie stays same-site. `/healthz` stays at the root for probes.

**Template workflow UI (#85):** `/templates` has Catalog, Custom templates, and Sync tabs.
Catalog selection adds exact template IDs to explicit sets; custom YAML can be pasted or uploaded;
Sync shows the safe upstream configuration, recent runs, and queues an operator-triggered refresh.
`/template-sets` edits exact, all-active, or exclude-mode membership, and the
admin node table exposes each node's active bundle digest/last push plus “Sync templates.”

## Architecture in one breath

Three services, split so the scanner is a disposable, credential-less execution engine:

- **backend** (`cmd/backend`) — system of record. Owns Postgres, dispatches scans to a
  scanner node, **polls** it to completion, pulls JSONL results, and ingests findings.
  All finding dedup/lifecycle logic lives here.
- **scanner node** (`cmd/scanner`) — runs the `nuclei` **binary** (not the SDK) against a
  scan spec and serves results over HTTP. **Holds no DB credentials.** Bearer-token auth.
- **Postgres** — data + (later) the dispatch queue/schedules. Findings stored as `JSONB`
  plus the preserved raw line; byte-exact raw output is also archived to S3-compatible storage.

Traffic is strictly **backend → scanner** (dispatch, poll, pull). The node never calls back.

## Invariants — do not break these

1. **The scanner node must never gain database access.** It receives a spec, returns
   results. This is the core security boundary.
2. **Results flow by polling, not callbacks** — keep the backend → node direction one-way.
3. **Nuclei is invoked as a binary/subprocess**, so upgrades stay "bump the image."
4. **Backend is the only system of record** — the node is stateless/in-memory per run.
5. **Don't hand-roll solved problems — use prominent, well-maintained libraries.**
   UUIDs, crypto, auth/token handling, and similar correctness-sensitive primitives must
   be library calls, not reimplementations (e.g. IDs go through `types.NewID()`, which
   delegates to `github.com/google/uuid`). The bias toward the standard library applies
   only where stdlib is genuinely a first-class solution (HTTP routing via `ServeMux`
   method+pattern matching on Go 1.22+, `encoding/json`, `log/slog`) — it is **not** a
   reason to reinvent something a mature library already does well. Avoid heavy frameworks
   where stdlib suffices; reach for a proven lib where it doesn't.

## Layout

```
cmd/backend        backend entrypoint (main + graceful shutdown + PG retry)
cmd/scanner        scanner node entrypoint
internal/types     wire contracts shared by both services + Nuclei JSONL parse structs
internal/scanner   Runner (runs nuclei, process-group cancel/timeout) + optional naabu port-discovery pre-pass (discover.go, #86) + HTTP API
internal/backend   Orchestrator (dispatch/poll/ingest + raw archive) + Scheduler (cron ticker) + ScannerClient + scanner node registry (nodes.go config-seeder + nodes_http.go admin API; DB-backed, dispatch picks the node whose CIDRs match the target — #22) + HealthMonitor (health.go; polls each node's GET /v1/capabilities for liveness, dispatch fails fast to a known-unhealthy node — #98) + per-node mTLS (client_tls.go; each node stores its own server-CA/client-cert/client-key in the registry, client_key write-only like the token; clientForNode builds a TLS-aware ScannerClient — #26) + ObjectStore (objectstore.go, S3/MinIO) + HTTP API + OIDC/BFF auth (auth.go, authz.go) + audit-log middleware (audit.go)
internal/store     Postgres access + embedded migrations (internal/store/migrations/*.sql)
web/               React + TS + Vite SPA; embedded into the backend via go:embed (web/embed.go)
deploy/            Dockerfile.backend (SPA build + distroless), Dockerfile.scanner, keycloak/ (seeded realm)
docker-compose.yml postgres + minio + keycloak + scanner + backend
.github/workflows/ CI (build/vet/test + SPA) and release (images → GHCR)
docs/ARCHITECTURE.md   design decisions (source of truth); ADMIN_GUIDE.md, API.md, DEVELOPMENT.md are the practical guides
```

The frontend build output `web/dist` is git-ignored except a committed empty `.gitkeep`,
which keeps the directory non-empty so `//go:embed all:dist` compiles and `go build` works
on a fresh clone; the Docker image builds the real SPA. Nothing Vite emits is tracked, so
`npm run build` never dirties the tree — if `git status` ever shows a file under `web/dist`,
that's a bug, not something to commit. Without a build, `/` serves a "frontend not built"
notice (`notBuiltHTML` in `web/embed.go`) instead of failing. Frontend dev:
`cd web && npm install && npm run dev` (proxies `/api` to :8080).

## Commands

Go is installed via Homebrew; use `/opt/homebrew/bin/go` (may not be on PATH in all shells).

```sh
/opt/homebrew/bin/go build ./...      # compile
/opt/homebrew/bin/go vet ./...        # vet
/opt/homebrew/bin/go test ./...       # unit tests
/opt/homebrew/bin/gofmt -l .          # list unformatted files (fix with gofmt -w)
```

Run the full stack (requires Docker — see the environment notes below):

```sh
cp .env.example .env    # change SCANNER_TOKEN (at least 32 chars, e.g. `openssl rand -base64 24`;
                        # shorter crash-loops the scanner); if you also rotate OIDC_CLIENT_SECRET,
                        # change it in deploy/keycloak/realm-nsc.json before the realm is first imported
docker compose up --build
```

Then log in at `http://localhost:8080`. The API is under `/api/*` behind the session cookie
(there is **no** implicit default scan — every scan names a `scan_policy_id` and stored
`target_id`).
See `docs/API.md` for the endpoint walkthrough and `docs/ADMIN_GUIDE.md` for auth-disabled
dev mode used in headless `curl` testing.

## Environment notes

- **Docker is installed** (Docker Desktop). The full backend↔Postgres↔scanner loop **can** be
  run locally via `docker compose up --build` — prefer verifying a change end-to-end against
  the real stack over reasoning about it. The daemon is not always running: if `docker info`
  fails, `open -a Docker` and wait a few seconds for it to come up.
- Only claim the loop was verified if it actually ran; state which parts were exercised.
- **The scanner node CAN be smoke-tested standalone** (no DB needed): build `cmd/scanner`,
  run it with `SCANNER_TOKEN` set and `NUCLEI_PATH` pointing anywhere, and exercise the API
  (health → 200, missing token → 401, valid → 202, unknown id → 404). Installing `nuclei`
  locally (`brew install nuclei`) enables a real end-to-end scanner-half run.
- Use the session scratchpad for throwaway binaries/output, not the repo tree.

## Conventions

- Structured logging via `log/slog` (JSON handler).
- Agent-created branches use `feature/<name>` for feature work and `fix/<name>` for bug fixes; do not use the `codex/` prefix in this repository.
- Config via environment variables (see the table in `docs/ADMIN_GUIDE.md`); required vars fail fast.
- Errors wrapped with `%w` and context; HTTP handlers return plain-text errors + status.
- `internal/store/migrations/0001_init.sql` is the consolidated fresh-deployment baseline,
  **frozen at the first beta release and immutable — never edit it or any other applied
  migration file** (the runner stores SHA-256 checksums and fails fast if a checksummed
  migration's contents change). Every schema change goes in a new numbered file under
  `internal/store/migrations/`; the runner applies unseen files in filename order and records
  them in `schema_migrations`. Fix mistakes to applied migrations with a separately named
  repair/forward migration. Alpha databases are not upgradeable and are rejected at startup;
  the preserved `testdata/alpha_migrations/` chain is now a sealed test-only reference (its
  digest is pinned in `migration_integration_test.go`) — do not append to it.
- Run `gofmt -w`, `go vet`, and `go test` before considering a change done.
- **Dependency review (recurring):** at a natural review boundary, scan for hand-rolled code
  that duplicates a mature library (per invariant #5) and for unused/heavy deps to drop.
  Introducing a dependency is a deliberate choice — prefer widely-used, actively-maintained
  libraries with a compatible license; note the rationale in the change.
