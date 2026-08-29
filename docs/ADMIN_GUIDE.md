# Administration guide

The operator guide lives in [`docs/admin/`](admin/). That directory is the **source of truth**.
GitHub Actions publishes it to the
[GitHub wiki](https://github.com/Nikolasel/nuclei-security-center/wiki) on every push to `main`
and on every `v*` version tag. Do not edit the wiki in the GitHub UI; those edits are overwritten
on the next publish.

> [!IMPORTANT]
> Beta deployments start from an **empty Postgres database**. Alpha databases are not upgradeable to
> beta: the schema baseline was frozen at the alpha→beta boundary, so back up any data you need to
> retain, deploy with a new empty database, and move portable data with template/template-set exports
> and scan bundles. The backend rejects an unsupported migration history at startup instead of
> attempting a partial upgrade. From beta onward, schema changes ship as new numbered migrations that
> apply forward on an existing database.

## Chapters

| Chapter | Topics |
|---|---|
| [Home](admin/Home.md) | How this guide is published |
| [Deployment](admin/Deployment.md) | Requirements, Compose, GHCR images, production |
| [Configuration](admin/Configuration.md) | Environment variables |
| [Authentication](admin/Authentication.md) | OIDC/BFF, sessions, service accounts, mTLS |
| [First-run bootstrap](admin/First-run-bootstrap.md) | First sign-in through the first successful scan |
| [Operations](admin/Operations.md) | Targets, templates, policies, schedules, scanner fleet |
| [Findings and data](admin/Findings-and-data.md) | Lifecycle, exports, audit, backups, upgrades |
| [Troubleshooting](admin/Troubleshooting.md) | Symptom table |

When adding or changing an environment variable, update
[Configuration](admin/Configuration.md) in the same pull request.
