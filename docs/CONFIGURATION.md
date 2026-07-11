# Configuration

All configuration is via environment variables; required variables fail fast on startup. The
compose stack sets sane defaults for local use — this reference is for tuning and cloud
deployment.

## Environment variables

| Variable | Service | Default | Purpose |
|---|---|---|---|
| `BACKEND_ADDR` | backend | `:8080` | listen address |
| `DATABASE_URL` | backend | – (required) | Postgres DSN |
| `SCANNER_URL` | backend | `http://localhost:8081` | scanner node base URL |
| `SCANNER_TOKEN` | both | – (required, **min 32 chars**) | bearer token for backend → node calls; the node refuses to start below the floor. Mint from a CSPRNG, e.g. `openssl rand -base64 24` |
| `SCANNER_ADDR` | scanner | `:8081` | listen address |
| `NUCLEI_PATH` | scanner | `nuclei` | path to the nuclei binary |
| `SCANNER_WORK_DIR` | scanner | – (unset ⇒ a private `0700` temp dir) | per-scan working dirs; leave unset for an auto-created process-exclusive dir, or point at a mounted private volume |
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

## Authentication (OIDC/BFF)

The backend is a confidential OIDC client (the [BFF pattern](ARCHITECTURE.md#6-security-right-sized--not-the-enterprise-maximum)):
it runs the login flow server-side and hands the browser only an **httpOnly session cookie** —
no tokens ever reach JavaScript. **Roles come from the IdP**: a `groups` claim is mapped to
`admin` / `operator` / `viewer`. Authorization per endpoint — reads need `viewer`, running scans
and config writes need `operator`, deletes need `admin`.

The compose stack wires a **Keycloak** IdP seeded with realm `nsc`, a `nuclei-backend` client,
the three groups, and one demo user each (username = password):

| User | Password | Role |
|---|---|---|
| `admin` | `admin` | admin |
| `operator` | `operator` | operator |
| `viewer` | `viewer` | viewer |

Open `http://localhost:8080` and the SPA redirects you to Keycloak; after login it drops you
back into the app with a session cookie. The raw endpoints: `GET /api/auth/login` starts the
flow, `GET /api/auth/me` returns your identity + roles, `POST /api/auth/logout` ends the session.
Keycloak's own admin console is at `http://localhost:8082` (`admin`/`admin`).

Because protected endpoints authenticate via the **session cookie** (not a bearer token), drive
the API from the browser or a cookie jar populated by a real login.

> **Pure-API smoke testing without auth:** unset `OIDC_ISSUER` (comment it out in
> `docker-compose.yml`) to run the backend in **auth-disabled dev mode** — every request acts as
> an all-roles dev user, so the `curl` examples in the [API reference](API.md) work directly. The
> backend logs a loud warning in this mode.

To point at a real IdP (Cognito, Entra, Keycloak, …), set `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET`, and `APP_BASE_URL`, register the `OIDC_REDIRECT_URL` with the provider, and
map its group claim to the three roles via `OIDC_ROLES_CLAIM` + `OIDC_*_GROUP`.

## Object storage

Raw scan output is archived to an S3-compatible bucket (see
[API → Raw scan-output archive](API.md#raw-scan-output-archive) for behavior). Enable it by
setting `S3_ENDPOINT`; leave it unset to disable archiving (the default in dev). The bucket named
by `S3_BUCKET` is created on startup if it doesn't exist. In the cloud, point these at the managed
object store — S3, GCS (S3 API), or Azure Blob:

| Environment | Object store | `S3_ENDPOINT` |
|---|---|---|
| Local / compose | MinIO | `minio:9000` |
| AWS | S3 | `s3.<region>.amazonaws.com` |
| GCP | GCS (S3-compat) | `storage.googleapis.com` |
| Azure | Blob | via an S3 gateway or an `ObjectStore` swap (`gocloud.dev/blob`) |
