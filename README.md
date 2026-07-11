# nuclei-security-center

A web interface for running and triaging [Nuclei](https://github.com/projectdiscovery/nuclei)
scans. Architecture and build plan: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```sh
git clone git@github.com:Nikolasel/nuclei-security-center.git
```

## Status: Phases 1–3 complete

A logged-in user manages targets + template sets, runs scans from them, and
browses findings in a React UI. Under the hood: **backend dispatches → scanner
node syncs templates + runs nuclei → backend polls, pulls results, and ingests
findings into Postgres**, all behind OIDC/BFF auth.

On top of that: a **Tenable-style finding lifecycle** (dedup + detection state +
dispositions), **cron scheduling**, **exports** (JSON/CSV/SARIF/raw), a structured
**audit log**, per-scan **raw-output archival** to object storage, and a **scope
guardrail** that keeps scans inside approved targets. Next is Phase 4 (cloud deploy +
hardening) — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
browser ─▶ React SPA (served by backend at /) ─▶ /api/* (session cookie, roles)
              │
POST /api/scans ─▶ backend ──dispatch──▶ scanner node ──▶ nuclei ──▶ results.jsonl
                    │  ◀────poll/pull──────────┘
                    └─▶ Postgres (scans, findings)
```

### Layout

```
cmd/backend      backend entrypoint (system of record + orchestrator)
cmd/scanner      scanner node entrypoint (credential-less nuclei runner)
internal/types   wire contracts shared by both services
internal/scanner scanner node: runs nuclei, serves results over HTTP
internal/backend orchestrator (dispatch/poll/ingest), scanner client, HTTP API, OIDC/BFF auth
internal/store   Postgres access + embedded migrations
web/             React + TS + Vite SPA (embedded into the backend via go:embed)
deploy/          Dockerfiles + seeded Keycloak realm
docker-compose.yml   postgres + minio + keycloak + scanner + backend
```

## Run it

Requires Docker (Go and the SPA both compile inside the build containers).

```sh
cp .env.example .env          # then edit SCANNER_TOKEN + OIDC_CLIENT_SECRET
docker compose up --build
```

Then open **http://localhost:8080** and log in (demo users below).

Services: backend + UI on `:8080`, scanner on `:8081`, Postgres on `:5432`,
Keycloak on `:8082` (OIDC IdP), MinIO on `:9000` (console `:9001`, staged for
Phase 3, not yet wired).

## API

The JSON API lives under `/api/*` and is guarded by the session cookie (see
[Authentication](#authentication-oidcbff)). The examples below assume a cookie
jar `jar.txt`, or [auth-disabled dev mode](#authentication-oidcbff) for headless use.

**Scans.** A scan must name a stored **target** (`target_id`) or an ad-hoc `spec`; every host
it targets has to fall inside an approved target record (the [scope guardrail](#scope-guardrail)).
Create a target first (see the **Config** examples below), then:

```sh
# start a scan from a stored target
curl -sb jar.txt -X POST localhost:8080/api/scans \
  -H 'content-type: application/json' -d '{"target_id":"<id>"}'   # => {"scan_id":"..."}
# check scan state (queued → running → complete)
curl -sb jar.txt localhost:8080/api/scans/<scan_id>
# occurrences observed by one scan (paginated envelope: {items,total,limit,offset})
curl -sb jar.txt "localhost:8080/api/scans/<scan_id>/findings" | jq
```

An empty body (or targets outside every approved target) is rejected `400` — there is no
implicit default scan, so the scanner can't be fat-fingered at out-of-scope assets.

**Findings lifecycle (Phase 2).** Findings are **deduplicated** across scans and
tracked over time with a **Tenable Security Center-style** lifecycle. `GET /api/findings`
returns the deduplicated entities (keyed on `(target, template, matched_at)`). Each has:

- a **detection state** — derived from scan observation, never stored. **Closure is
  evidence-driven — there is no manual "fixed."** The state is a function of whether the
  finding is in the target's latest completed scan and how many times it has come back
  after disappearing (`times_mitigated`):

  | Detection state | In latest scan? | Meaning |
  |---|---|---|
  | `new` | yes | first time ever observed |
  | `active` | yes | seen before, never gone |
  | `resurfaced` | yes | was mitigated, now detected again — a **regression** |
  | `mitigated` | no | previously seen; the latest scan no longer finds it (auto-closed) |
  | `previously_mitigated` | no | mitigated, came back, and is gone again — a **flapping** finding |

  `resurfaced` is to `active` what `previously_mitigated` is to `mitigated`: same current
  presence, but "…and this has disappeared before." Both need attention a clean
  `active`/`mitigated` doesn't — a regressed fix, or a vuln that keeps reappearing.
- a manual **disposition** — `none` / `false_positive` / `accepted` (Accept Risk, with an
  optional `accept_expires_at`; an expired acceptance reverts to the detection state) —
  and an optional **`recast_severity`** (Recast Risk).
- an **`effective_state`** and **`effective_severity`** overlaying the two (an `accepted`
  or `false_positive` disposition wins; otherwise you see the detection state).

`GET /api/scans/{id}/findings` (above) returns the immutable per-scan **occurrences** instead.

```sh
# deduplicated lifecycle list (paginated + filtered)
curl -sb jar.txt "localhost:8080/api/findings" | jq
# one tracked finding + full raw Nuclei output of its latest occurrence
curl -sb jar.txt "localhost:8080/api/findings/<finding_id>" | jq
# disposition (operator) — none | false_positive | accepted (+ optional accept_expires_at)
curl -sb jar.txt -X PATCH localhost:8080/api/findings/<finding_id>/disposition \
  -H 'content-type: application/json' \
  -d '{"disposition":"accepted","note":"risk accepted for Q3","accept_expires_at":"2027-01-01T00:00:00Z"}'
# recast severity (operator) — empty severity clears the recast
curl -sb jar.txt -X PATCH localhost:8080/api/findings/<finding_id>/severity \
  -H 'content-type: application/json' -d '{"severity":"high","note":"internet-facing"}'
```

`GET /api/findings` supports server-side filtering + pagination: `q` (name/template
substring), `severity` (comma-separated, any-of, matched against the effective severity),
`host` (substring), `cve` (substring), `tag` (exact), `disposition` (exact), `state`
(exact effective state), plus `target_id`, `limit`, `offset`. CVE ids and tags are
promoted to indexed columns so these filters are cheap.

```sh
curl -sb jar.txt "localhost:8080/api/findings?severity=critical,high&state=new&limit=50" | jq
```

**Export (Phase 2).** The deduplicated lifecycle list exports as **JSON**, **CSV**,
**SARIF 2.1.0**, or **raw JSONL** via `GET /api/findings/export?format=…`. The export takes
the *same* filter params as `/api/findings`, so you export exactly what you're looking at
(unpaginated). CSV is a flat table for spreadsheets; SARIF is a valid 2.1.0 document (deduped
rules + per-finding results, severity→level) for code-scanning / CI ingestion. The projected
formats carry our lifecycle overlay — detection state, disposition, `times_mitigated`. **Raw
JSONL** instead emits the *verbatim Nuclei output* of each finding's latest occurrence, one
JSON object per line (Nuclei's native `out.jsonl` shape) — the full request/response, curl
reproducer, and classification that the projected formats drop.

```sh
# every critical/high finding still active, as CSV
curl -sb jar.txt "localhost:8080/api/findings/export?format=csv&severity=critical,high&state=active" -o findings.csv
# the same filter as SARIF, e.g. to upload to GitHub code scanning
curl -sb jar.txt "localhost:8080/api/findings/export?format=sarif&severity=critical,high" -o findings.sarif
# raw Nuclei JSONL (verbatim scanner output) for the current view
curl -sb jar.txt "localhost:8080/api/findings/export?format=raw&severity=critical,high" -o findings.jsonl
```

Every format carries the **lifecycle finding `id`** as a shared join key — a column in CSV,
`id` in JSON, `properties.nsc_lifecycle_id` in SARIF, and `_nsc_lifecycle_id` on each raw
JSONL line (a namespaced field that doesn't collide with Nuclei's) — so a raw export joins
back to the projected triage data (and to `GET /api/findings/{id}`) on one key.

The SPA offers the same four formats from an **Export** menu on the Findings view.

**Schedules (Phase 2).** A schedule runs a target (+ optional template set) on a **cron**
cadence, unattended. A backend ticker wakes each minute and dispatches the schedules whose
next fire time has arrived — through the same path as an ad-hoc scan, so scheduled scans are
tracked in the finding lifecycle exactly like manual ones (a scheduled scan carries
`source: "schedule"`). Postgres is the source of truth: enable/disable and the next-run time
persist across restarts, and a run missed while the backend was down fires once on the next
tick, then reschedules forward.

```sh
# create a schedule: nightly scan of a target at 03:00 (5-field cron; also
# accepts @hourly/@daily/… and "@every 30m")
curl -sb jar.txt -X POST localhost:8080/api/schedules -H 'content-type: application/json' -d '{
  "name": "nightly-prod",
  "target_id": "<target_id>",
  "template_set_id": "<template_set_id>",
  "cron": "0 3 * * *",
  "enabled": true
}'
# list schedules (each shows next_run_at / last_run_at / last_scan_id)
curl -sb jar.txt localhost:8080/api/schedules | jq
# pause a schedule (edit) — enabled:false clears its next run
curl -sb jar.txt -X PUT localhost:8080/api/schedules/<id> -H 'content-type: application/json' \
  -d '{"name":"nightly-prod","target_id":"<target_id>","cron":"0 3 * * *","enabled":false}'
# dispatch once now, off-schedule (leaves the cron cadence untouched)
curl -sb jar.txt -X POST localhost:8080/api/schedules/<id>/run     # => {"scan_id":"..."}
curl -sb jar.txt -X DELETE localhost:8080/api/schedules/<id>       # remove
```

Reads need `viewer`; create/edit/run need `operator`; delete needs `admin`. The SPA exposes
all of this on the **Schedules** page (cron presets, enable/disable toggle, run-now).

Override the target/templates with an ad-hoc spec (note the `spec` wrapper). Every host in
`spec.targets` must still fall inside an approved target — here `scanme.sh` must already exist
as a target host, or the request is rejected `400` (see [Scope guardrail](#scope-guardrail)):

```sh
curl -sb jar.txt -X POST localhost:8080/api/scans -H 'content-type: application/json' -d '{
  "spec": {
    "targets": ["scanme.sh"],
    "templates": {"severities": ["info","low"], "tags": ["tech"]},
    "options": {"rate_limit": 150, "concurrency": 25, "timeout_sec": 600}
  }
}'
```

**Config.** Reusable **targets** (a named host allowlist) and **template sets**
(severity/tag/path filters + optional pinned git ref) to launch scans from:

```sh
# create a target (the hosts list is the scope allowlist)
curl -sb jar.txt -X POST localhost:8080/api/targets -d '{"name":"prod-web","hosts":["scanme.sh"],"tags":["prod"]}'
# create a template set
curl -sb jar.txt -X POST localhost:8080/api/template-sets -d '{"name":"info","severities":["info","low"]}'
# launch a scan from stored config
curl -sb jar.txt -X POST localhost:8080/api/scans -d '{"target_id":"<id>","template_set_id":"<id>"}'
```

Both resources support the full REST set: `GET|POST /api/targets`,
`GET|PUT|DELETE /api/targets/{id}` (and likewise `/api/template-sets`). Deleting a
target or template set nulls the link on past scans but never deletes scan history.

## Scope guardrail

A scan may only target hosts that fall inside an **approved target record** — the union of
all your targets' hosts is the allowlist. This is the most important guardrail: for an active
scanner, accidentally aiming at out-of-scope or third-party assets is the difference between a
tool and an incident. Scans launched from a stored `target_id` (and schedules) are in scope by
construction; ad-hoc `spec` scans are validated and matched against the allowlist before
dispatch, and anything outside it is rejected `400` before the scanner is ever contacted.

Matching is **host-granular and never resolves DNS**: exact hostname (no wildcard, so
`example.com` does **not** authorize `sub.example.com`), IP-in-CIDR, and CIDR-within-CIDR;
ports and URL paths are ignored (the asset is the host). It **fails closed** — with no
approved targets, every scan is rejected until you add one.

## Authentication (OIDC/BFF)

The backend is a confidential OIDC client (the [BFF pattern](docs/ARCHITECTURE.md)):
it runs the login flow server-side and hands the browser only an **httpOnly session
cookie** — no tokens ever reach JavaScript. **Roles come from the IdP**: a `groups`
claim is mapped to `admin` / `operator` / `viewer`. Authorization per endpoint —
reads need `viewer`, running scans and config writes need `operator`, deletes need
`admin`.

The compose stack wires a **Keycloak** IdP seeded with realm `nsc`, a `nuclei-backend`
client, the three groups, and one demo user each (username = password):

| User | Password | Role |
|---|---|---|
| `admin` | `admin` | admin |
| `operator` | `operator` | operator |
| `viewer` | `viewer` | viewer |

Just open `http://localhost:8080` and the SPA redirects you to Keycloak; after
login it drops you back into the app with a session cookie. The raw endpoints:
`GET /api/auth/login` starts the flow, `GET /api/auth/me` returns your identity +
roles, `POST /api/auth/logout` ends the session. Keycloak's own admin console is
at `http://localhost:8082` (`admin`/`admin`).

Because protected endpoints authenticate via the **session cookie** (not a bearer
token), drive the API from the browser or a cookie jar populated by a real login.

> **Pure-API smoke testing without auth:** unset `OIDC_ISSUER` (comment it out in
> `docker-compose.yml`) to run the backend in **auth-disabled dev mode** — every
> request acts as an all-roles dev user, so the `curl` examples above work directly.
> The backend logs a loud warning in this mode.

## Audit log

Every mutating API call (create / update / delete / scan-dispatch / triage) emits one
structured **`event=audit`** line to **stdout** — there is no audit table and no in-app
audit screen by design. In the cloud the container's stdout is already shipped to a log
aggregator (CloudWatch, Azure Log Analytics, GCP Cloud Logging, Loki, …); that system owns
retention, indexing, and querying, and because the trail lives off the app database a DB
compromise can't rewrite it.

Each event carries the actor (`actor_subject` / `actor_email`), an `event_id`, the
fine-grained `action`, the object (`object_type` / `object_id`), `method`, `path`, `status`,
and `duration_ms`. `event_id` is a small, stable vocabulary to build detections on:

| `event_id` | emitted when |
|---|---|
| `access_denied` | a mutating call is rejected by authorization (HTTP 403) |
| `config_changed` | a target, template set, or schedule is created / updated / deleted |
| `scan_dispatched` | a scan is submitted (ad-hoc) or a schedule is run |
| `finding_triaged` | a finding's disposition or severity recast changes |

All audit events log at **INFO** — a denial is authorization working as intended, not a
fault — so alerting keys off `event_id` / `status`, not the log level. Tail them locally with:

```sh
docker compose logs -f backend | grep '"event":"audit"'
```

## Develop

Backend:

```sh
go build ./...   # embeds web/dist (a placeholder until the SPA is built)
go vet ./...
go test ./...
```

Frontend (`web/`) — hot-reload dev server that proxies `/api` to the backend.
Run the backend in **auth-disabled dev mode** (unset `OIDC_ISSUER`) so the SPA
sees an all-roles dev user without the cross-origin login dance; real OIDC is
exercised through the compose stack.

```sh
cd web
npm install
npm run dev        # http://localhost:5173, proxies /api → :8080
npm run build      # type-check + produce web/dist for embedding
```

## Config

| Variable | Service | Default | Purpose |
|---|---|---|---|
| `BACKEND_ADDR` | backend | `:8080` | listen address |
| `DATABASE_URL` | backend | – (required) | Postgres DSN |
| `SCANNER_URL` | backend | `http://localhost:8081` | scanner node base URL |
| `SCANNER_TOKEN` | both | – (required) | bearer token for backend → node calls |
| `SCANNER_ADDR` | scanner | `:8081` | listen address |
| `NUCLEI_PATH` | scanner | `nuclei` | path to the nuclei binary |
| `SCANNER_WORK_DIR` | scanner | `/tmp/nuclei-scans` | per-scan working dirs |
| `OIDC_ISSUER` | backend | – (unset ⇒ auth **disabled**) | OIDC issuer URL; setting it enables auth |
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
| `COOKIE_SECURE` | backend | `false` | set the cookie `Secure` flag (enable behind TLS) |
| `S3_ENDPOINT` | backend | – (unset ⇒ archiving **disabled**) | S3/MinIO endpoint `host:port` (no scheme); setting it enables raw-output archiving |
| `S3_BUCKET` | backend | `nuclei-raw` | bucket for archived raw output (created on startup if absent) |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | backend | – | S3 credentials |
| `S3_REGION` | backend | `us-east-1` | S3 region |
| `S3_USE_SSL` | backend | `false` | use TLS to the S3 endpoint |

## Raw scan-output archive

Each scan's verbatim Nuclei output (`out.jsonl`) is archived to an S3-compatible bucket —
MinIO in the Compose stack, any S3 API in the cloud. Postgres remains the system of record
for the projected findings; the bucket holds the bulky, write-once evidence. Archiving is
**best-effort**: if the upload fails, the scan still succeeds (the findings are already
ingested) and it's logged, not fatal.

Download a completed scan's archive (streamed back through the backend, behind your session):

```sh
curl -s localhost:8080/api/scans/<scan-id>/raw -o scan.jsonl
```

The scan-detail page shows a **Download raw output** link once the archive exists (`has_raw`).
With `S3_ENDPOINT` unset the feature is off and the endpoint returns 404.
