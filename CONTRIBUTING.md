# Contributing to nuclei-security-center

Thanks for your interest in contributing. This is an active beta; the design decisions live in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — read the relevant section before investing in a
large change, and open an issue first for anything that touches the architecture, the security
model, or a public API contract.

## Before you start

- **Found a vulnerability?** Do not open a public issue. Report it privately via
  [SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting).
- Want to work on an issue? Comment on it so effort isn't duplicated.
- By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Toolchain for the local verification gates below: **Go 1.25+** (`go.mod`
requires `go 1.25.0`) and **Node 22** (CI pins it; Vite 8 needs `^20.19 ||
>=22.12`).

The full stack is the baseline — it boots everything the SPA needs
(Postgres + MinIO + Keycloak + scanner + backend):

```sh
cp .env.example .env    # change SCANNER_TOKEN: the scanner fails fast under 32
                        # chars — generate one with `openssl rand -base64 24`
docker compose up --build
```

Then open http://localhost:8080 and log in with a demo user (`admin` / `admin`).

> If you also rotate `OIDC_CLIENT_SECRET`, change it in
> `deploy/keycloak/realm-nsc.json` **before the realm is first imported** —
> the seeded realm ships the same development secret as `.env.example`, and a
> mismatch breaks the OIDC login.

**SPA hot reload (Vite on :5173):** `npm run dev` only proxies `/api` to a
backend already listening on `:8080` — and it must be a **separate** backend,
not the compose one (its OIDC login redirects to `:8080`, so sessions can't
complete through the dev server). Bring up the stack's services, then run an
auth-disabled backend on top. It fails fast without `DATABASE_URL` and
`SCANNER_TOKEN`, and `SCANNER_URL` must not target `localhost` (the node-seed
validator rejects the default). On an empty database the dev `SCANNER_URL`
seeds the default node; on an existing compose database the stored node
(e.g. `http://scanner:8081`) wins and is only reachable from containers —
use a fresh DB (or edit the node via the admin API) for real local scans.

Two terminals (`go run` is a server — it never returns):

Terminal 1 — the auth-disabled backend:

```sh
docker compose stop backend          # frees :8080 for the local backend
docker compose up -d postgres scanner

# SCANNER_URL: a host-reachable LAN IP of this machine (macOS: `ipconfig
# getifaddr en0`; Linux: `hostname -I | cut -d' ' -f1`); localhost is rejected.
DATABASE_URL='postgres://nuclei:nuclei@localhost:5432/nuclei?sslmode=disable' \
SCANNER_TOKEN="$(grep -m1 '^SCANNER_TOKEN=' .env | cut -d= -f2)" \
SCANNER_URL="http://<host-lan-ip>:8081" \
BACKEND_ADDR=:8080 AUTH_DISABLED=true go run ./cmd/backend
```

Terminal 2 — the SPA:

```sh
cd web && npm install && npm run dev   # http://localhost:5173; proxies /api to :8080
```

Full details in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Verifying your change

Before a PR is ready, these must pass locally:

```sh
gofmt -l .            # must print nothing (fix with gofmt -w)
go vet ./...
go build ./...
go test ./...         # fast local path — store/backend integration tests skip without NSC_TEST_DATABASE_URL
cd web && npm run build   # tsc -b + vite build
```

CI is stricter than the local path above. It always sets `NSC_TEST_DATABASE_URL`
and runs:

```sh
go test -race -count=1 ./...   # race detector + no test-result cache + full integration suite
```

So plain `go test ./...` can pass locally and still fail CI (race detector,
skipped integration tests). Exercise the riskier paths you touched against a
disposable Postgres with `NSC_TEST_DATABASE_URL` set — see
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — or expect the CI run to be the
judge.

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

The schema baseline (`internal/store/migrations/0001_init.sql`) **froze at the first beta
release and is immutable — never edit it**, and never edit any applied numbered migration:
the runner checksums recorded files and fails fast if contents change.

Each schema change goes in a **new numbered SQL file** under `internal/store/migrations/`
(e.g. `0003_….sql`); the runner applies unseen files in filename order and records them in
`schema_migrations`. To fix a mistake in an applied migration, add a separately named
forward/repair migration instead of editing. Migration SQL must be transaction-compatible
(no `CREATE INDEX CONCURRENTLY` — see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)). Legacy
alpha databases are rejected at startup; do not add compatibility or upgrade logic for them.
If you're unsure, ask in the issue.

## Pull requests

- Branch naming: `feature/<name>` or `fix/<name>`.
- One logical change per PR; keep diffs focused.
- Commit messages follow Conventional Commits with a scope, e.g.
  `fix(scan-policies): collapse execution knobs into summary column (#276)`, referencing the
  issue number.
- CI must be green. Only maintainers merge (squash merge or an explicit merge commit, at the
  reviewer's discretion), so keep the PR title descriptive and address review before merge.
- Update docs (`README.md`, `docs/*`) when behavior or configuration changes.

## Style

- Structured logging via `log/slog` (JSON handler) — no `fmt.Println` in server paths.
- Errors wrapped with `%w` and context; HTTP handlers return plain-text errors + status.
- Config via environment variables, failing fast on missing required values.
