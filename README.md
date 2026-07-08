# nuclei-security-center

A web interface for running and triaging [Nuclei](https://github.com/projectdiscovery/nuclei)
scans. Architecture and build plan: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```sh
git clone git@github.com:Nikolasel/nuclei-security-center.git
```

## Status: Phase 0 (the spine)

Phase 0 proves the whole architecture end-to-end with no auth, UI, or scheduling
yet: **backend dispatches → scanner node syncs templates + runs nuclei → backend
polls, pulls results, and ingests findings into Postgres.**

```
POST /scans ──▶ backend ──dispatch──▶ scanner node ──▶ nuclei ──▶ results.jsonl
                  │  ◀────poll/pull──────────┘
                  └─▶ Postgres (scans, findings)
```

### Layout

```
cmd/backend      backend entrypoint (system of record + orchestrator)
cmd/scanner      scanner node entrypoint (credential-less nuclei runner)
internal/types   wire contracts shared by both services
internal/scanner scanner node: runs nuclei, serves results over HTTP
internal/backend orchestrator (dispatch/poll/ingest), scanner client, HTTP API
internal/store   Postgres access + embedded migrations
deploy/          Dockerfiles
docker-compose.yml   postgres + minio + scanner + backend
```

## Run it

Requires Docker (Go compiles inside the build containers).

```sh
cp .env.example .env          # then edit SCANNER_TOKEN
docker compose up --build
```

Services: backend on `:8080`, scanner on `:8081`, Postgres on `:5432`,
Keycloak on `:8082` (OIDC IdP), MinIO on `:9000` (console `:9001`, staged for
Phase 3, not yet wired).

### Trigger the Phase 0 scan

With an empty body the backend runs its default scan against ProjectDiscovery's
public test host `scanme.sh` — no infrastructure of your own needed.

```sh
# start a scan
curl -s -X POST localhost:8080/scans
# => {"scan_id":"..."}

# check scan state (queued → running → complete)
curl -s localhost:8080/scans/<scan_id>

# list ingested findings
curl -s "localhost:8080/findings?scan_id=<scan_id>" | jq
```

You can override the target/templates with an ad-hoc spec (note the `spec` wrapper):

```sh
curl -s -X POST localhost:8080/scans -H 'content-type: application/json' -d '{
  "spec": {
    "targets": ["scanme.sh"],
    "templates": {"severities": ["info","low"], "tags": ["tech"]},
    "options": {"rate_limit": 150, "concurrency": 25, "timeout_sec": 600}
  }
}'
```

## Config API (Phase 1)

Manage reusable **targets** (a named host allowlist) and **template sets** (severity/
tag/path filters + optional pinned git ref), then launch scans from them.

```sh
# create a target (the hosts list is the scope allowlist)
curl -s -X POST localhost:8080/targets -d '{"name":"prod-web","hosts":["scanme.sh"],"tags":["prod"]}'

# create a template set
curl -s -X POST localhost:8080/template-sets -d '{"name":"info","severities":["info","low"]}'

# launch a scan from stored config
curl -s -X POST localhost:8080/scans -d '{"target_id":"<id>","template_set_id":"<id>"}'
```

Both resources support the full REST set: `GET|POST /targets`,
`GET|PUT|DELETE /targets/{id}` (and likewise `/template-sets`). Deleting a target or
template set nulls the link on past scans but never deletes scan history.

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

Log in by visiting `http://localhost:8080/auth/login` in a browser — Keycloak
authenticates you and redirects back with a session cookie. `GET /auth/me` returns
your identity + roles; `POST /auth/logout` ends the session. Keycloak's own admin
console is at `http://localhost:8082` (`admin`/`admin`).

Because protected endpoints authenticate via the **session cookie** (not a bearer
token), drive them from the browser or a cookie jar:

```sh
# log in (opens Keycloak, sets the cookie in the jar)
curl -sc jar.txt -L "localhost:8080/auth/login"   # follow the browser flow instead for real login
curl -sb jar.txt localhost:8080/auth/me | jq
curl -sb jar.txt -X POST localhost:8080/scans
```

> **Pure-API smoke testing without auth:** unset `OIDC_ISSUER` (comment it out in
> `docker-compose.yml`) to run the backend in **auth-disabled dev mode** — every
> request acts as an all-roles dev user, so the `curl` examples above work directly.
> The backend logs a loud warning in this mode.

## Develop

```sh
go build ./...
go vet ./...
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
| `OIDC_REDIRECT_URL` | backend | `APP_BASE_URL`+`/auth/callback` | callback URL registered with the IdP |
| `POST_LOGIN_REDIRECT` | backend | `APP_BASE_URL`+`/` | where the browser lands after login |
| `OIDC_SCOPES` | backend | `openid,profile,email` | requested scopes |
| `OIDC_ROLES_CLAIM` | backend | `groups` | ID-token claim holding the user's groups/roles |
| `OIDC_ADMIN_GROUP` / `OIDC_OPERATOR_GROUP` / `OIDC_VIEWER_GROUP` | backend | `admin` / `operator` / `viewer` | group value → role mapping |
| `SESSION_TTL` | backend | `12h` | session lifetime (Go duration) |
| `SESSION_COOKIE_NAME` | backend | `nsc_session` | session cookie name |
| `COOKIE_SECURE` | backend | `false` | set the cookie `Secure` flag (enable behind TLS) |
