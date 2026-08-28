# Contributing to nuclei-security-center

Thanks for your interest in contributing. This is an active beta; the design decisions live in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — read the relevant section before investing in a
large change, and open an issue first for anything that touches the architecture, the security
model, or a public API contract.

## Before you start

- **Found a vulnerability?** Do not open a public issue. Report it privately via
  [SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting).
- Want to work on an issue? Comment on it so effort isn't duplicated.

## Development setup

```sh
cd web && npm install && npm run dev   # SPA on :5173, proxies /api to :8080
```

Full stack (Postgres + MinIO + Keycloak + scanner + backend):

```sh
cp .env.example .env    # change SCANNER_TOKEN
docker compose up --build
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for auth-disabled dev mode and headless `curl`
testing. Go is required locally (or run everything inside the containers).

## Verifying your change

All of these must pass before a PR is ready (CI runs them too):

```sh
gofmt -l .            # must print nothing (fix with gofmt -w)
go vet ./...
go build ./...
go test ./...         # some store tests need NSC_TEST_DATABASE_URL; they skip without it
cd web && npm run build   # tsc -b + vite build
```

## Invariants

Changes that break these will be rejected — they are the core security model
(see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)):

1. The scanner node must never gain database access.
2. Results flow by polling, not callbacks — traffic is strictly backend → scanner.
3. Nuclei (and naabu) are invoked as pinned binaries, not SDKs.
4. The backend + Postgres are the only system of record; nodes stay stateless per run.
5. Don't hand-roll solved problems: use prominent, well-maintained libraries for
   crypto, UUIDs, auth primitives, etc.

## Migrations

The project is pre-beta: schema changes are folded into
`internal/store/migrations/0001_init.sql` (the fresh-deployment baseline) together with the
alpha fixture chain under `internal/store/testdata/alpha_migrations/`. After the first beta
release the baseline freezes and new changes get numbered migration files. If you're unsure,
ask in the issue.

## Pull requests

- Branch naming: `feature/<name>` or `fix/<name>`.
- One logical change per PR; keep diffs focused.
- Commit messages follow Conventional Commits with a scope, e.g.
  `fix(scan-policies): collapse execution knobs into summary column (#276)`, referencing the
  issue number.
- CI must be green; the repo squashes merges, so a tidy PR title beats a tidy commit series.
- Update docs (`README.md`, `docs/*`) when behavior or configuration changes.

## Style

- Structured logging via `log/slog` (JSON handler) — no `fmt.Println` in server paths.
- Errors wrapped with `%w` and context; HTTP handlers return plain-text errors + status.
- Config via environment variables, failing fast on missing required values.
