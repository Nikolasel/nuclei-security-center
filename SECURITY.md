# Security Policy

`nuclei-security-center` is a tool for running and triaging vulnerability scans, so we take
its own security seriously. Thanks for helping keep it and its users safe.

## Supported versions

The project is in active beta development. Security fixes land on the latest `main` and the
most recent tagged release; older tags are not maintained.

| Version | Supported |
|---|---|
| latest `main` / newest release | ✅ |
| older releases | ❌ |

## Reporting a vulnerability

**Please report vulnerabilities privately — do not open a public issue, PR, or discussion.**

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and click
**Report a vulnerability** to start a private advisory visible only to the maintainers.

Please include:

- the affected component — backend, scanner node, or the SPA;
- the version or commit SHA;
- a description of the issue and its impact;
- reproduction steps or a proof of concept.

We aim to acknowledge a report within a few business days and will keep you updated as we
triage, fix, and coordinate a release. Please give us reasonable time to ship a fix before any
public disclosure, and avoid accessing or modifying data that isn't yours while investigating.

## Security model

The security-relevant design decisions are documented in
[docs/ARCHITECTURE.md §6](docs/ARCHITECTURE.md#6-security-right-sized--not-the-enterprise-maximum).
In short:

- **The scanner node holds no database credentials** and is reachable only backend → node
  (dispatch/poll/pull) — a compromised node in a segmented network can't reach the system of
  record.
- **Scope guardrail:** scans may only target hosts inside an approved target record, matched
  before dispatch, and it **fails closed** (no approved targets ⇒ every scan is rejected).
- **Authentication** is OIDC via the BFF pattern — access/refresh tokens stay server-side and
  the browser only ever holds an httpOnly session cookie. RBAC is enforced on every mutating
  endpoint. Cookie-authenticated mutations additionally require an exact `Origin` match to
  `APP_BASE_URL` (or `Sec-Fetch-Site: same-origin` when `Origin` is absent), and JSON bodies must
  declare `Content-Type: application/json`; service-account bearer callers are explicit and do
  not rely on ambient cookies. `GET /api/auth/logout` is the only tightly scoped exception: it
  additionally accepts a direct browser navigation (`Sec-Fetch-Site: none` with no `Origin`) so an
  address-bar/bookmark visit still terminates both sessions, while site-controlled
  `cross-site`/`same-site` navigations remain blocked; both logout endpoints fail closed when
  `APP_BASE_URL` is missing or malformed.
- **Audit trail:** every mutating call is emitted as a structured log event to stdout for the
  platform's log aggregator, off the app database.

## A note on operating a scanner

This project drives an **active vulnerability scanner**. Only scan hosts you are authorized to
scan — the scope guardrail helps enforce that, but the responsibility is ultimately the
operator's.
