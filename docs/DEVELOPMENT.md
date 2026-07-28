# Development

## Backend

```sh
go build ./...   # embeds web/dist (a placeholder until the SPA is built)
go vet ./...
go test ./...
gofmt -l .       # list unformatted files (fix with gofmt -w)
```

Structured logging is via `log/slog` (JSON handler). Schema changes go in a new numbered file
under `internal/store/migrations/`; the runner applies unseen files in filename order and records
them in `schema_migrations`. Run `gofmt -w`, `go vet`, and `go test` before considering a change
done.

The template-aware finding-lifecycle regression has an opt-in real-PostgreSQL test. Point it only
at a disposable test database; it applies migrations and creates then removes isolated test rows:

```sh
NSC_TEST_DATABASE_URL='postgres://nuclei:nuclei@localhost:5432/nuclei?sslmode=disable' \
  go test ./internal/store -run TestTemplateAwareLifecyclePostgres -count=1 -v
```

## Frontend

The SPA lives in `web/` and is embedded into the backend binary via `go:embed`. For hot-reload
development, run the Vite dev server and the backend in **auth-disabled dev mode** (unset
`OIDC_ISSUER`, see [Configuration](CONFIGURATION.md#authentication-oidcbff)) so the SPA sees an
all-roles dev user without the cross-origin login dance; real OIDC is exercised through the
compose stack.

```sh
cd web
npm install
npm run dev        # http://localhost:5173, proxies /api → :8080
npm run build      # type-check (tsc -b) + produce web/dist for embedding
```

The build output `web/dist` is git-ignored except a committed placeholder `index.html`, so
`go build` can embed something before a real SPA build. The Docker image builds the real SPA in a
Node stage and copies it in before compiling the backend.

## Standalone scanner smoke test

The scanner node needs no database, so it can be run and exercised on its own: build
`cmd/scanner`, run it with `SCANNER_TOKEN` set and `NUCLEI_PATH` pointing anywhere, and hit the
API (health → 200, missing token → 401, valid dispatch → 202, unknown id → 404). Installing
`nuclei` locally (`brew install nuclei`) enables a real end-to-end run of the scanner half.

## Discovery on Docker Desktop (macOS) reports every host as alive

**Symptom:** during the `discovering` phase the scan detail shows `N hosts responding`
where N equals the CIDR size of your target (`256` for a `/24`), and stays there. The
"Discovered endpoints" list eventually reports the *real* count (e.g. `2 hosts · 15
ports`) — so the per-host Nuclei line and the endpoints list are correct; only the live
discovery tally is inflated.

**Cause:** Docker Desktop on macOS does not bridge container networking onto the host's
L2 segment — it runs Linux in a hidden VM and NATs traffic. naabu's `-with-host-discovery`
(ICMP echo + TCP SYN/ACK to 80/443) against a non-routable address gets an answer from
the VM's NAT gateway rather than a real host, so naabu counts the whole `/24` as alive.
The same scan on a Linux host (`bridge`/`macvlan` networking) or against routable/internet
targets returns the correct handful. This is a property of the toolchain's view of the
network, not a scanner defect — the live host count is read from naabu's stderr and is only
as accurate as naabu's L3 reachability.

**What to do:**

- Don't chase the tally — the authoritative answer is the persisted `discovered_targets`
  (the post-scan endpoint list), parsed from naabu's JSON output, not the stderr tally.
- For day-to-day dev, set `NAABU_SCAN_TYPE=connect` on the scanner service in
  `docker-compose.yml`. Connect mode does no host discovery, so it can't false-alive; it
  still narrows Nuclei to the open ports it finds, in seconds. (On sparse *routable* ranges
  SYN is faster because it prunes dead hosts first — see [Architecture §4](ARCHITECTURE.md).)
- For accurate SYN behavior, run the stack on a Linux host with `bridge` networking, or point
  it at a routable/internet target. Treat the macOS dev path as a known-false-positive
  environment, not a representative test of host discovery.

**Verify you're in this case:** in the execution-log archive for the scan (download from the
scan detail, or `mc cat local/scans/<id>/raw.jsonl` against local MinIO), the count of
`Found alive host` lines equals the tally; if it equals the CIDR size, it's the NAT case.

## Continuous integration & releases

CI/CD runs on GitHub Actions (`.github/workflows/`):

- **CI** (`ci.yml`) — on every push to `main` and every pull request: a Go job (gofmt check,
  `go vet`, `go build`, `go test -race`) and an SPA job (`npm ci`, then `npm run build`, which
  runs `tsc -b`). Superseded runs on the same ref are cancelled.
- **Release** (`release.yml`) — on a `v*` tag (`git tag v0.4.0 && git push origin v0.4.0`):
  gated on `go test`, then builds and pushes the **backend** and **scanner** images to private
  GHCR — `ghcr.io/nikolasel/nuclei-security-center-{backend,scanner}` — tagged with the full
  semver, `major.minor`, and the commit `sha`, using a GHCR layer cache. Auth is the built-in
  `GITHUB_TOKEN` (`packages: write`), so no PAT is needed; the packages are private by default.

## Conventions

- Config via environment variables (see [Configuration](CONFIGURATION.md)); required vars fail
  fast.
- Errors wrapped with `%w` and context; HTTP handlers return plain-text errors + status.
- Don't hand-roll solved problems — UUIDs, crypto, auth/token handling, and cron parsing go
  through mature libraries (`github.com/google/uuid`, `github.com/robfig/cron/v3`,
  `github.com/minio/minio-go/v7`). The stdlib bias applies only where stdlib is genuinely
  first-class (HTTP routing via `ServeMux`, `encoding/json`, `log/slog`).
- At a natural review boundary, scan for hand-rolled code that duplicates a mature library and
  for unused/heavy deps to drop; introducing a dependency is a deliberate, noted choice.
