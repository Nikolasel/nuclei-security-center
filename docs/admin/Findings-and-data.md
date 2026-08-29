# Findings and data

## Findings, triage, exports, and scan bundles

NSC keeps immutable per-scan **occurrences** and a globally deduplicated **finding lifecycle**.
Detection state is derived from scan evidence:

| State | Meaning |
|---|---|
| `new` | First observation. |
| `active` | Still observed and never previously mitigated. |
| `resurfaced` | Previously mitigated, now observed again. |
| `mitigated` | Absent from the latest scan that proved the exact template reached the exact endpoint. |
| `previously_mitigated` | Flapped: mitigated, resurfaced, and absent again. |

Closure is evidence-driven; there is no manual “fixed.” Missing/invalid request-trace coverage fails
closed, and a completed scan that skipped malformed or oversized finding records cannot provide
negative mitigation evidence. Analysts may apply `false_positive` or optionally time-bounded `accepted` dispositions and
recast severity.

The lifecycle list exports as JSON, CSV, SARIF, or raw Nuclei JSONL with the same filters used in the
UI. Raw lifecycle export uses the latest occurrence; the per-scan object archive remains the
byte-exact scanner output.

A scan bundle exports one complete scan result as JSON or zip, including its config snapshots,
resolved template IDs/digest, coverage, and occurrences. It intentionally excludes analyst
lifecycle overlays. Import recomputes identity and derives lifecycle state on the destination; use
bundles to move scan results between fresh deployments.

## Audit logging

Every mutating API request emits one structured log record to backend stdout with `event=audit`.
Records include actor and actor type, action, object type/id, HTTP status, duration, and a stable
`event_id`. Dispatch events also include policy, target, and scan IDs; unattended schedules use
`actor_type=system`.

There is deliberately no audit table in PostgreSQL. Configure the platform log collector for:

- durable retention and access control;
- searches/alerts on `event_id` such as `access_denied`, `config_changed`, `scan_dispatched`,
  `finding_triaged`, and `service_account_changed`;
- detection of repeated denied access, unexpected scope changes, and service-token changes; and
- protection against application/database administrators rewriting historical audit records.

## Backups, retention, and upgrades

- Back up PostgreSQL using the managed service's native snapshots/PITR. It contains configuration,
  scan records, occurrences, lifecycle state, sessions, and template catalog.
- Apply bucket lifecycle/backup policy separately for raw archives and execution logs.
- Configure scan retention in **Settings**. The policy is DB-backed; `RETENTION_SWEEP_INTERVAL` only
  controls polling frequency.
- Back up custom templates/template sets with portability exports and scan results with bundles when
  moving environments.
- Rotate DB credentials through `DATABASE_PASSWORD_FILE` using a secret-rendering sidecar/agent.
  Leading/interior whitespace is preserved and trailing CR/LF is trimmed.
- The schema baseline (`0001_init.sql`) is frozen as of the beta release. Migrations are ordered and
  checksum-immutable; never edit an applied migration — add a new numbered forward migration instead.
- Do not point beta at an alpha database. The startup rejection is intentional; deploy fresh.
