# nuclei-security-center

A web interface for running and triaging [Nuclei](https://github.com/projectdiscovery/nuclei)
scans, built for a small internal security/eng team and portable to any cloud.

A logged-in user defines **targets** and **template sets**, runs scans (on demand or on a
**cron schedule**), and triages the results through a **Tenable-style finding lifecycle** —
dedup, evidence-driven detection state (new / active / resurfaced / mitigated), and analyst
dispositions (accept-risk / false-positive / recast). Findings export as JSON / CSV / SARIF /
raw JSONL. Complete scans export/import as versioned scan bundles (JSON or zip). A **scope
guardrail** keeps every scan inside approved targets, every mutating call
is written to a structured **audit log**, and raw scanner output is archived to object storage.

## Architecture

Three services, split so the scanner is a disposable, credential-less execution engine:

- **backend** — the system of record. Owns Postgres, runs OIDC/BFF auth, dispatches scans,
  polls the scanner to completion, ingests findings, and serves the API + embedded SPA.
- **scanner node** — runs the `nuclei` binary against a scan spec and serves results over HTTP.
  Holds no database credentials.
- **Postgres** + an **S3-compatible object store** (for the raw-output archive).

```
browser ─▶ React SPA (served by backend at /) ─▶ /api/* (session cookie, roles)
              │
POST /api/scans ─▶ backend ──dispatch──▶ scanner node ──▶ nuclei ──▶ results.jsonl
                    │  ◀────poll/pull──────────┘
                    └─▶ Postgres (scans, findings) + S3 (raw archive)
```

Traffic is strictly backend → scanner. See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for
the design rationale.

Both services ship as multi-arch (`linux/amd64` + `linux/arm64`) images on a minimal **Red Hat UBI
10 Micro** base; the scanner is fully self-contained, baking in a checksum-verified, pinned `nuclei`
binary (`NUCLEI_VERSION`) and `naabu`. The backend-owned template catalog is pushed to nodes as a
verified bundle; the image contains no mutable community template cache. See
**[Administration guide → Deployment](docs/ADMIN_GUIDE.md#1-deployment)**.

## Quick start

Requires Docker (Go and the SPA both compile inside the build containers).

```sh
cp .env.example .env          # set SCANNER_TOKEN + OIDC_CLIENT_SECRET
docker compose up --build
```

Open **http://localhost:8080** and log in with a demo user (`admin` / `admin`,
`operator` / `operator`, or `viewer` / `viewer`). The compose stack runs backend + UI on `:8080`,
the scanner on `:8081`, plus Postgres, MinIO, and a seeded Keycloak IdP.

> **Beta deployments must start with an empty PostgreSQL database.** Alpha databases are not
> upgradeable; the backend rejects their migration history instead of attempting a partial upgrade.

## Repository layout

```
cmd/backend      backend entrypoint (system of record + orchestrator)
cmd/scanner      scanner node entrypoint (credential-less nuclei runner)
internal/types   wire contracts shared by both services
internal/scanner scanner node: runs nuclei, serves results over HTTP
internal/backend orchestrator, scanner client, HTTP API, OIDC/BFF auth, audit log, scope guardrail
internal/store   Postgres access + embedded migrations
web/             React + TS + Vite SPA (embedded into the backend via go:embed)
deploy/          Dockerfiles + seeded Keycloak realm
docker-compose.yml   postgres + minio + keycloak + scanner + backend
```

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** — design principles, components, data model, and decisions.
- **[API reference](docs/API.md)** — REST endpoints for scans, findings, dispositions, exports, and schedules.
- **[Administration guide](docs/ADMIN_GUIDE.md)** — deployment, environment variables, authentication, bootstrap, operations, audit, and troubleshooting.
- **[Development](docs/DEVELOPMENT.md)** — local dev workflow, auth-disabled mode, tests, and CI/CD.

## License

[AGPL-3.0](LICENSE) — copyleft, including the network-use clause. Anyone running a
modified version as a service must publish the source of their modifications.
