# Development

Operational deployment and configuration belong in the [Administration guide](ADMIN_GUIDE.md).
This document covers the local edit/test loop.

## Backend

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .       # fix listed files with gofmt -w
```

Structured logs use `log/slog` with a JSON handler. Errors should wrap causes with `%w`; HTTP
handlers return plain-text errors plus an appropriate status.

### Database migrations

`internal/store/migrations/0001_init.sql` is the consolidated fresh-deployment baseline, frozen at
the beta release with the schema carried over from the final alpha. It is now immutable; do not edit
it. Alpha databases are intentionally rejected; do not add compatibility or upgrade logic for them.

From beta onward, each schema change goes in a new numbered SQL file. The runner serializes startup
migration work per database/schema, validates the complete recorded history, and applies unseen files
plus their history records in one transaction. Files run in filename order and use SHA-256 checksums
in `schema_migrations`. Applied files are immutable: never edit one after a database may have recorded
it; add a forward/repair migration instead. Migration SQL must be transaction-compatible:
`CREATE INDEX CONCURRENTLY` and other statements prohibited inside a transaction cannot run through
this runner. Introduce a deliberate out-of-transaction migration mechanism before such an operation
is required; do not silently weaken the atomic migration contract.

Real-PostgreSQL tests are opt-in so the ordinary suite needs no service container. Point them only at
a disposable database; each test creates and drops an isolated schema:

```sh
NSC_TEST_DATABASE_URL='postgres://nuclei:***@localhost:5432/nuclei?sslmode=disable' \
  go test ./internal/store -count=1 -v
```

`TestBaselineMatchesAlphaChainPostgres` applies the preserved historical chain and the consolidated
baseline to separate schemas, dumps both with `pg_dump --schema-only`, and requires identical
normalized DDL. Install `pg_dump`, put it on `PATH`, or set `NSC_TEST_PG_DUMP=/path/to/pg_dump`.

## Full local stack

```sh
cp .env.example .env    # change SCANNER_TOKEN (at least 32 chars — `openssl rand -base64 24`;
                        # shorter crash-loops the scanner); if you rotate OIDC_CLIENT_SECRET, match
                        # it in deploy/keycloak/realm-nsc.json before the realm is first imported
docker compose up --build
```

Open <http://localhost:8080>. This exercises real OIDC through seeded Keycloak plus Postgres, MinIO,
and the scanner. Only claim end-to-end verification when the stack and a scan were actually run.

## Frontend

The React/TypeScript SPA lives in `web/` and is embedded into the backend. For hot reload, use two
terminals (`go run` is a server — it never returns). `npm run dev` only proxies `/api` to the
backend, so it must already be up — and it must be this separate auth-disabled backend, not the
compose one (whose OIDC login redirects to `:8080`, breaking the dance through the dev server).
The backend fails fast without `DATABASE_URL` and `SCANNER_TOKEN`, and `SCANNER_URL` must not
target `localhost` (the node-seed validator rejects the default even when the node row exists;
use this machine's LAN IP — on macOS `ipconfig getifaddr en0`, on Linux `hostname -I | cut -d' ' -f1`).

Terminal 1 — services up, compose backend stopped to free `:8080`:

```sh
docker compose stop backend && docker compose up -d postgres scanner
DATABASE_URL='postgres://nuclei:nuclei@localhost:5432/nuclei?sslmode=disable' \
SCANNER_TOKEN="$(grep -m1 '^SCANNER_TOKEN=' .env | cut -d= -f2)" \
SCANNER_URL="http://<host-lan-ip>:8081" \
BACKEND_ADDR=:8080 AUTH_DISABLED=true go run ./cmd/backend
```

Terminal 2 — SPA (leave terminal 1 running):

```sh
cd web
npm install
npm run dev        # http://localhost:5173; proxies /api to :8080
```

`npm run build` (type-check + production bundle into `web/dist`) is not part of the
hot-reload loop — it belongs with the pre-PR gates, see “Continuous integration and releases”
and [CONTRIBUTING.md](../CONTRIBUTING.md).

`web/dist` is ignored except for its committed placeholder, allowing a fresh Go build before the
real SPA exists. Docker builds the SPA before compiling the backend.

## Standalone scanner smoke test

The scanner has no database dependency. Build `cmd/scanner`, provide a 32+ character
`SCANNER_TOKEN`, and point `NUCLEI_PATH`/`NAABU_PATH` at available binaries. Exercise health,
unauthorized/authorized dispatch, unknown scan, cancellation, and result endpoints. Installing
Nuclei/Naabu locally enables a real scanner-half run.

## Docker Desktop discovery caveat

Docker Desktop on macOS runs Linux behind VM/NAT networking. SYN host discovery against private
ranges can report every address alive even though the final open-port set is correct. The persisted
`discovered_targets` is authoritative; the live count is only Naabu's view of the network.

For routine macOS development, use `NAABU_SCAN_TYPE=connect`. Verify SYN/raw-socket behavior on a
Linux host or routable network. See [Administration troubleshooting](ADMIN_GUIDE.md#9-troubleshooting).

## Continuous integration and releases

GitHub Actions runs:

- Go formatting, vet, build, and race-enabled tests;
- real-PostgreSQL store and backend integration tests, including baseline/alpha equivalence,
  lifecycle behavior, scope enforcement, and scan-bundle round trips; CI disables Go's test-result
  cache so every run exercises the fresh PostgreSQL service;
- `npm ci` and the production SPA build; and
- on `v*` tags, tests followed by multi-architecture backend/scanner image publication to GHCR.

Before opening a PR, run the repository-wide Go gates and the SPA production build. Keep generated
`web/dist` output untracked.

## Conventions

- Agent-created feature branches use `feature/<name>`; fixes use `fix/<name>`.
- Configuration is environment-based; update [ADMIN_GUIDE.md](ADMIN_GUIDE.md) when adding a variable.
- Preserve the scanner boundary: no database access and no scanner→backend callback path.
- Use mature libraries for UUIDs, crypto, auth, object storage, and cron parsing rather than
  hand-rolling solved primitives.
