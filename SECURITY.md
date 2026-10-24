# Security policy

Goodnight Check is a tool for running and triaging vulnerability scans, so we take its own
security seriously. Thanks for helping keep it and its users safe.

## Reporting a vulnerability

Please report vulnerabilities privately. Do not open a public issue, pull
request or discussion.

- **GitHub:** open the **Security** tab of this repository and choose
  **Report a vulnerability**.
- **Email:** `security@goodnightsec.com`.

Please include:

- the affected component and version, or the commit;
- what the vulnerability is and what an attacker could do with it;
- the steps to reproduce it, or a proof of concept.

Please do not access or change data that is not yours, and do not disrupt
any service while you investigate.

## What we commit to

- We acknowledge your report within 3 business days.
- We aim to assess it within 7 business days and tell you the result.
- We agree the disclosure date with you, at most 90 days after your
  report. We publish a security advisory with the fix, and credit you if
  you wish.

## Supported versions

| Version | Supported |
|---|---|
| `v0.5.0` and newer | Yes |
| Older releases | No |

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

Goodnight Check drives an **active vulnerability scanner**. Only scan hosts you are authorized to
scan — the scope guardrail helps enforce that, but the responsibility is ultimately the
operator's.
