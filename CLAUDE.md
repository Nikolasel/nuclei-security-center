# CLAUDE.md

Guidance for agentic runs in this repo. Keep it current when structure or conventions change.

## What this is

`nuclei-security-center` — a web interface for running and triaging [Nuclei](https://github.com/projectdiscovery/nuclei)
scans, for a small internal security/eng team, built cloud-portable.
Repo: `git@github.com:Nikolasel/nuclei-security-center.git`.

**`docs/ARCHITECTURE.md` is the source of truth for design decisions and the phase plan.**
Read it before making architectural changes. `README.md` covers running the stack.

Current status: **Phase 1 is complete** (targets/template-set CRUD, scan-from-config,
OIDC/BFF auth with IdP-driven roles, and the React SPA). **Phase 2 is in progress** — the
**finding-lifecycle** slice is done (dedup + first/last-seen + a Tenable-style detection
lifecycle + dispositions/recast); **scheduling** and **exports** are the remaining Phase 2
slices. See §8 of the architecture doc.

**Findings are two tables now (Phase 2):** `findings` is the immutable per-scan
**occurrence** log (holds the verbatim raw JSONL; answers "what did scan X observe");
`finding_lifecycle` is the **deduplicated** entity keyed on `(target_id, template_id,
matched_at)` that users triage. Ingest inserts an occurrence and upserts the lifecycle row
(`store.IngestFinding`). The lifecycle follows **Tenable Security Center's model**, two
dimensions:

- **Detection state** — derived at read time (vs. the target's latest completed scan) plus
  a stored `times_mitigated` counter, never a stored state: `new` / `active` / `resurfaced`
  (still detected) and `mitigated` / `previously_mitigated` (gone). **Closure is
  evidence-driven; there is no manual "fixed."** `times_mitigated` is bumped at ingest when
  a finding reappears after being absent from the previous scan.
- **Disposition** (manual overlay, the only stored state): `none` / `false_positive` /
  `accepted` (Accept Risk; `accept_expires_at` optional — an expired acceptance falls back
  to the detection state) + `recast_severity` (Recast Risk). `effective_state` /
  `effective_severity` overlay disposition on detection.

`GET /api/findings` = lifecycle view (`state`/`disposition`/severity/… filters);
`GET /api/scans/{id}/findings` = occurrences; `PATCH /api/findings/{id}/disposition` and
`PATCH /api/findings/{id}/severity` = analyst overlays (operator). Workflow dispositions
(investigating / in-progress) are intentionally deferred (see §8 "Beyond MVP").

The JSON API is served under **`/api/*`**; the React SPA (in `web/`) is built by Vite and
**embedded into the backend binary** (`go:embed`), served at `/` same-origin so the BFF
session cookie stays same-site. `/healthz` stays at the root for probes.

## Architecture in one breath

Three services, split so the scanner is a disposable, credential-less execution engine:

- **backend** (`cmd/backend`) — system of record. Owns Postgres, dispatches scans to a
  scanner node, **polls** it to completion, pulls JSONL results, and ingests findings.
  All finding dedup/lifecycle logic lives here.
- **scanner node** (`cmd/scanner`) — runs the `nuclei` **binary** (not the SDK) against a
  scan spec and serves results over HTTP. **Holds no DB credentials.** Bearer-token auth.
- **Postgres** — data + (later) the dispatch queue/schedules. Findings stored as `JSONB`
  plus the verbatim raw line; raw output also archived to S3-compatible storage (Phase 3).

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
internal/scanner   Runner (runs nuclei, process-group cancel/timeout) + HTTP API
internal/backend   Orchestrator (dispatch/poll/ingest) + ScannerClient + HTTP API + OIDC/BFF auth (auth.go, authz.go)
internal/store     Postgres access + embedded migrations (internal/store/migrations/*.sql)
web/               React + TS + Vite SPA; embedded into the backend via go:embed (web/embed.go)
deploy/            Dockerfile.backend (SPA build + distroless), Dockerfile.scanner, keycloak/ (seeded realm)
docker-compose.yml postgres + minio + keycloak + scanner + backend
docs/ARCHITECTURE.md   design + phased plan (source of truth)
```

The frontend build output `web/dist` is git-ignored except a committed placeholder
`index.html` (so `go build` can embed before a real build); the Docker image builds the
real SPA. Frontend dev: `cd web && npm install && npm run dev` (proxies `/api` to :8080).

## Commands

Go is installed via Homebrew; use `/opt/homebrew/bin/go` (may not be on PATH in all shells).

```sh
/opt/homebrew/bin/go build ./...      # compile
/opt/homebrew/bin/go vet ./...        # vet
/opt/homebrew/bin/go test ./...       # unit tests
/opt/homebrew/bin/gofmt -l .          # list unformatted files (fix with gofmt -w)
```

Run the full stack (requires Docker — see constraint below):

```sh
cp .env.example .env    # set SCANNER_TOKEN
docker compose up --build
curl -s -X POST localhost:8080/scans                    # default: scans scanme.sh
curl -s "localhost:8080/findings?scan_id=<id>" | jq
```

## Environment constraints

- **Docker is NOT installed on this machine.** The full backend↔Postgres↔scanner loop
  therefore can't be run locally — ask the user to `docker compose up --build` for
  end-to-end checks. Do not claim the full loop was verified locally.
- **The scanner node CAN be smoke-tested standalone** (no DB needed): build `cmd/scanner`,
  run it with `SCANNER_TOKEN` set and `NUCLEI_PATH` pointing anywhere, and exercise the API
  (health → 200, missing token → 401, valid → 202, unknown id → 404). Installing `nuclei`
  locally (`brew install nuclei`) enables a real end-to-end scanner-half run.
- Use the session scratchpad for throwaway binaries/output, not the repo tree.

## Conventions

- Structured logging via `log/slog` (JSON handler).
- Config via environment variables (see the table in `README.md`); required vars fail fast.
- Errors wrapped with `%w` and context; HTTP handlers return plain-text errors + status.
- New schema changes go in a new numbered file under `internal/store/migrations/`; the
  runner applies unseen files in filename order and records them in `schema_migrations`.
- Run `gofmt -w`, `go vet`, and `go test` before considering a change done.
- **Dependency review (recurring):** at each phase boundary, scan for hand-rolled code
  that duplicates a mature library (per invariant #5) and for unused/heavy deps to drop.
  Introducing a dependency is a deliberate choice — prefer widely-used, actively-maintained
  libraries with a compatible license; note the rationale in the change.
