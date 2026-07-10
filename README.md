# nuclei-security-center

A web interface for running and triaging [Nuclei](https://github.com/projectdiscovery/nuclei)
scans. Architecture and build plan: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```sh
git clone git@github.com:Nikolasel/nuclei-security-center.git
```

## Status: Phase 1 (usable product slice)

A logged-in user manages targets + template sets, runs scans from them, and
browses findings in a React UI. Under the hood: **backend dispatches → scanner
node syncs templates + runs nuclei → backend polls, pulls results, and ingests
findings into Postgres**, all behind OIDC/BFF auth.

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

**Scans.** With an empty body the backend runs its default scan against
ProjectDiscovery's public test host `scanme.sh` — no infrastructure of your own needed.

```sh
# start a scan
curl -sb jar.txt -X POST localhost:8080/api/scans          # => {"scan_id":"..."}
# check scan state (queued → running → complete)
curl -sb jar.txt localhost:8080/api/scans/<scan_id>
# occurrences observed by one scan (paginated envelope: {items,total,limit,offset})
curl -sb jar.txt "localhost:8080/api/scans/<scan_id>/findings" | jq
```

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

Override the target/templates with an ad-hoc spec (note the `spec` wrapper):

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
