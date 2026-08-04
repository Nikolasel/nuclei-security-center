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

`internal/store/migrations/0001_init.sql` is the beta baseline for fresh deployments. Alpha
databases are intentionally rejected; do not add compatibility or upgrade logic for them.

After beta, each schema change goes in a new numbered SQL file. The runner serializes startup
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

`TestBaselineMatchesAlphaChainPostgres` applies the preserved historical chain and the beta baseline
to separate schemas, dumps both with `pg_dump --schema-only`, and requires identical normalized
DDL. Install `pg_dump`, put it on `PATH`, or set `NSC_TEST_PG_DUMP=/path/to/pg_dump`.

## Frontend

The React/TypeScript SPA lives in `web/` and is embedded into the backend. For hot reload, run the
backend with `OIDC_ISSUER` unset and `AUTH_DISABLED=true`, then:

```sh
cd web
npm install
npm run dev        # http://localhost:5173; proxies /api to :8080
npm run build      # type-checks and produces web/dist
```

`web/dist` is ignored except for its committed placeholder, allowing a fresh Go build before the
real SPA exists. Docker builds the SPA before compiling the backend.

## Full local stack

```sh
cp .env.example .env
docker compose up --build
```

Open <http://localhost:8080>. This exercises real OIDC through seeded Keycloak plus Postgres, MinIO,
and the scanner. Only claim end-to-end verification when the stack and a scan were actually run.

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
  lifecycle behavior, scope enforcement, and scan-bundle round trips;
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
