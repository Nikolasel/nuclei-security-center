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
MinIO on `:9000` (console `:9001`, staged for Phase 3, not yet wired).

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

You can override the target/templates by POSTing a scan spec:

```sh
curl -s -X POST localhost:8080/scans -H 'content-type: application/json' -d '{
  "targets": ["scanme.sh"],
  "templates": {"severities": ["info","low"], "tags": ["tech"]},
  "options": {"rate_limit": 150, "concurrency": 25, "timeout_sec": 600}
}'
```

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
