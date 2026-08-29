# Administration guide

This guide covers deploying and operating Nuclei Security Center (NSC). For endpoint-level details,
see the [API reference](../API.md); for design rationale and security boundaries, see
[Architecture](../ARCHITECTURE.md).

`docs/admin/` in the repository is the **source of truth**. GitHub Actions publishes these files to
the [GitHub wiki](https://github.com/Nikolasel/nuclei-security-center/wiki) on every push to `main`
and on every `v*` version tag. Edit the Markdown in a pull request; do not edit the wiki in the
GitHub UI.

> [!IMPORTANT]
> Beta deployments start from an **empty Postgres database**. Alpha databases are not upgradeable to
> beta: the schema baseline was frozen at the alpha→beta boundary, so back up any data you need to
> retain, deploy with a new empty database, and move portable data with template/template-set exports
> and scan bundles. The backend rejects an unsupported migration history at startup instead of
> attempting a partial upgrade. From beta onward, schema changes ship as new numbered migrations that
> apply forward on an existing database.

## Chapters

- [Deployment](Deployment.md) — requirements, Docker Compose, published images, production
- [Configuration](Configuration.md) — environment variables
- [Authentication](Authentication.md) — OIDC/BFF, sessions, service accounts, mTLS
- [First-run bootstrap](First-run-bootstrap.md)
- [Operations](Operations.md) — targets, templates, policies, schedules, scanner fleet
- [Findings and data](Findings-and-data.md) — lifecycle, exports, audit, backups, upgrades
- [Troubleshooting](Troubleshooting.md)
