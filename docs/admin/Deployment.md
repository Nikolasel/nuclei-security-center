# Deployment

## Requirements

NSC needs:

- the backend and one or more scanner containers;
- PostgreSQL 16 or newer;
- an OIDC provider for production authentication;
- an S3-compatible object store if raw scan-output and execution-log archival is required; and
- network paths from the backend to every scanner, and from each scanner to its assigned targets.

The scanner holds no database credentials. Traffic is backend → scanner only; scanner nodes never
register with or call the backend. Keep scanner egress restricted to the networks each node is
intended to scan.

## Local Docker Compose deployment

```sh
cp .env.example .env
# Change SCANNER_TOKEN. Keep the seeded OIDC secret unless you update the realm too.
docker compose up --build
```

The seeded Keycloak client secret in `deploy/keycloak/realm-nsc.json` matches `.env.example`.
For local development, either leave that development-only `OIDC_CLIENT_SECRET` unchanged or,
before Keycloak first imports the realm, set the same replacement value in both `.env` and the
realm JSON. Changing only `.env` makes the OIDC callback's token exchange fail. If Keycloak already
imported the realm, recreate its Compose container after synchronizing both values (`docker compose
down`, then `docker compose up --build`); local Keycloak data lives in the container layer.

Open <http://localhost:8080>. The compose stack includes Postgres, MinIO, Keycloak, one scanner,
and the backend/SPA. Demo users use their username as the password:

| User | Role |
|---|---|
| `admin` | admin |
| `operator` | operator |
| `viewer` | viewer |

Keycloak's local admin console is at <http://localhost:8082> (`admin` / `admin`). These seeded
credentials and the compose defaults are for local development only.

A fresh backend creates `schema_migrations`, applies the current schema baseline, seeds the configured
default scanner node, and starts the scheduler, template sync/distribution, node-health monitor, and
retention sweeper.

## Run from published images

Each `v*` git tag publishes public multi-arch images to GHCR. Anonymous pull works; no
`docker login` is required:

```sh
# Replace with a tag from https://github.com/Nikolasel/nuclei-security-center/releases
# Git tag v0.4.2-beta → image tag 0.4.2-beta (the leading v is stripped).
VERSION=0.4.2-beta
docker pull ghcr.io/nikolasel/nuclei-security-center-backend:$VERSION
docker pull ghcr.io/nikolasel/nuclei-security-center-scanner:$VERSION
```

Coordinates:

- `ghcr.io/nikolasel/nuclei-security-center-backend:<version>`
- `ghcr.io/nikolasel/nuclei-security-center-scanner:<version>`

GHCR package names are lowercase.

To run those images with this repo's Compose stack (Postgres, MinIO, Keycloak), edit
`docker-compose.yml` **in place**: on the `backend` and `scanner` services, delete the
`build:` mapping and set `image:` instead. Leave `environment`, `ports`, `volumes`, and
the backend's `depends_on` (postgres/keycloak health, scanner, minio) in place:

```yaml
# backend — delete `build:`, set:
image: ghcr.io/nikolasel/nuclei-security-center-backend:0.4.2-beta
# scanner — delete `build:`, set:
image: ghcr.io/nikolasel/nuclei-security-center-scanner:0.4.2-beta
```

That YAML is not a drop-in second Compose file. `docker-compose.override.yml` (or a
second `-f`) merges mappings and would keep `build:` from `docker-compose.yml`; an
override must also set `build: !reset` on both services.

Then `docker compose up` without `--build`. Leaving `build:` in place, or passing
`--build`, compiles from this tree and retags over the pulled image.

Every tag publishes the full semver (no leading `v`) and a `sha-<short>` git SHA. A
non-prerelease also publishes a floating `major.minor` tag and `latest`. Prereleases such
as `0.4.2-beta` get neither, so `docker pull …:latest` and `…:0.4` 404 today. The GHCR
package UI labels the most recently published tag as “Latest”; that is not a `:latest`
image tag.

## Production deployment

1. Provision an empty PostgreSQL database and a bucket (optional but recommended).
2. Deploy one scanner per reachable network zone from
   `ghcr.io/nikolasel/nuclei-security-center-scanner:<version>` (see
   [Run from published images](#run-from-published-images)). Give every scanner a strong,
   distinct bearer token and TLS; use mTLS for untrusted segments.
3. Deploy `ghcr.io/nikolasel/nuclei-security-center-backend:<version>` with Postgres, OIDC,
   object-store, and initial scanner seed configuration.
4. Terminate browser TLS at the backend or an ingress and keep `COOKIE_SECURE=true`.
5. Plan for all existing browser sessions to require sign-in again when this session-hardening
   release is deployed: old session rows are not converted, and secure deployments also change the
   cookie name to the host-locked `__Host-` form.
6. Send backend stdout to the platform log aggregator; that is the audit trail.
7. Verify `/healthz`, sign in, and complete the [first-run bootstrap](First-run-bootstrap.md).

The published images are multi-architecture (`linux/amd64`, `linux/arm64`) Red Hat UBI 10 Micro
images. The scanner image contains pinned, checksum-verified `nuclei` and `naabu` binaries;
scanner upgrades are image upgrades, not in-place binary updates.
