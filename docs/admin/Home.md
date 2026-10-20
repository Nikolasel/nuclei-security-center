# Administration guide

This guide covers deploying and operating Goodnight Check. For endpoint-level details,
see the [API reference](../API.md); for design rationale and security boundaries, see
[Architecture](../ARCHITECTURE.md).

`docs/admin/` in the repository is the **source of truth**. GitHub Actions publishes these files to
the [GitHub wiki](https://github.com/goodnightsec/gn-check/wiki) on every push to `main`
and on every `v*` version tag. Edit the Markdown in a pull request; do not edit the wiki in the
GitHub UI.

> [!IMPORTANT]
> The schema baseline is frozen. From that point onward, schema changes ship as new numbered
> migrations that apply forward on an existing database. If this binary is older than the database
> it is pointed at, startup refuses to run — use that newer release. Move portable data with
> template/template-set exports and scan bundles.

## Chapters

- [Deployment](Deployment.md) — requirements, Docker Compose, published images, production
- [Configuration](Configuration.md) — environment variables
- [Authentication](Authentication.md) — OIDC/BFF, sessions, service accounts, mTLS
- [First-run bootstrap](First-run-bootstrap.md)
- [Operations](Operations.md) — targets, templates, policies, schedules, scanner fleet, scan email
- [Findings and data](Findings-and-data.md) — lifecycle, exports, audit, backups, upgrades
- [Troubleshooting](Troubleshooting.md)
