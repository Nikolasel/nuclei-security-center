# Operations

## Targets: define approved scope

Create named targets from hostnames, IPs, CIDRs, or URLs. Target validation is DNS-free and
host-granular. Every launch selects a stored target, so there is no API path for an arbitrary host.
Review `host_count` before scanning: a `/24` counts as 256 addresses, not one list item.

Deleting a target removes its future schedules and nulls links on historical scans; it does not
delete scan history.

## Template catalog and custom templates

- **Upstream templates** are sync-owned and read-only.
- **Custom templates** are stored losslessly in PostgreSQL.
- Every custom create/update is sent to a healthy scanner's pinned `nuclei -validate` before the
  transaction commits. Invalid YAML returns bounded diagnostics; validator unavailability returns
  `503`, and nothing is persisted.
- Sync history is retained and shows added, updated, removed, skipped, digest, and template count.
- A template removed upstream becomes unavailable rather than disappearing from history.

Upgrade Nuclei by rebuilding/deploying the scanner image with the pinned version, then verify node
capabilities and custom-template validation.

Routine template administration follows this workflow:

1. An **operator** runs upstream sync and reviews the recorded sync result.
2. An **operator** creates or updates custom YAML; a healthy scanner validates it before commit.
3. An **operator** creates an `exact`, `all`, or `exclude` set and verifies its effective members.
4. An **admin** pushes/syncs the current catalog bundle to nodes; viewers may inspect status.
5. A **viewer** may export templates/sets, while an **operator** may import with `skip`, `overwrite`,
   or deterministic `rename` conflict handling.

## Template sets

Choose the mode deliberately:

| Mode | Behavior |
|---|---|
| `exact` | Stores explicit template IDs. Best for tightly controlled/reproducible policy selection. |
| `all` | Resolves every active template at dispatch. Follows catalog growth automatically. |
| `exclude` | Resolves every active template except an explicit deny-list. |

Empty exact sets and exclude sets that resolve to zero templates fail closed. Exact sets containing
unavailable IDs must be repaired before dispatch. A custom template referenced by an exclude-set
deny-list cannot be deleted until that exclusion is removed, preventing accidental re-enablement.

Catalog/templates and sets export as lossless YAML archives or JSON. Imports support `skip`,
`overwrite`, and deterministic `rename` conflict policies. All selected custom writes are validated
in one bounded batch and committed atomically; one invalid file prevents the entire selected batch.

## Scan policies

A policy is reusable **how to scan** configuration. It selects one template set and optional Nuclei
and discovery knobs. The target is selected independently at launch/schedule time, allowing one
policy to run across multiple approved scopes.

Discovery is enabled by default unless a policy disables it. Naabu narrows targets to open
`host:port` pairs before Nuclei. SYN mode is fastest on suitable Linux networking; connect mode is
an unprivileged fallback. Discovery errors/timeouts fail the scan closed rather than silently
running Nuclei against the unfiltered range.

## Schedules

A schedule combines a policy, target, and cron expression. PostgreSQL stores enablement and next/last
run state. The scheduler wakes each minute; a run missed while the backend was down fires once after
restart and then advances normally. **Run now** performs an off-cycle dispatch without changing the
cadence.

Use case-insensitively unique names and pause a schedule before changing a target/policy with broad
scope.

## Scanner fleet

The scanner registry in PostgreSQL is authoritative. `SCANNER_URL` and `SCAN_ZONES` only seed names
that do not exist; they never overwrite admin edits or delete nodes.

- CIDR assignments must not overlap across nodes.
- A node with no CIDRs is the catch-all for hostnames and unmatched IPs.
- All IP targets in one scan must map to the same node.
- Deleting the last catch-all is refused.
- `max_concurrent_scans` is configured independently per node in **Scanner Nodes**. It bounds both
  backend polling goroutines and node-side scan admission. If the backend's local view is full,
  `POST /api/scans` returns HTTP `429` without creating a scan row. If the node's independent gate
  is full, the already-admitted backend dispatch retries with bounded exponential backoff (capped at
  four seconds) without marking the scan failed; the backend admission still bounds the number of
  waiting dispatches. The default is `20`, with a hard range of `1`–`100`.
- Dispatch fails fast when the selected node is known unhealthy.
- Bundle distribution targets only stale, idle nodes; a busy node may return `409` until its scan
  releases the active template tree.

## Scan email notifications

When `SMTP_HOST` is set, the backend mails **one digest per completed scan that changed the
lifecycle**, and a separate alert when a scan **fails**. A run that changed nothing is silent.

The digest uses the same evidence rules as the findings list:

| Status | Meaning |
|---|---|
| New | First seen on this scan. |
| Changed | Resurfaced: previously mitigated, observed again (`times_mitigated` bumped). |
| Fixed | Absent from this covering scan, and the previous covering scan had observed it. Announced once. |

Counts are by **effective severity** (a recast wins). Live `accepted` / `false_positive` findings
are omitted; `active` findings never appear. Unproven request-trace coverage cannot produce Fixed
lines. Metadata drift (template sync rewriting name/severity) and analyst triage edits are not
mailed. Links point at `APP_BASE_URL` `/scans/{id}` and `/findings/{id}`; recipients sign in
normally.

Mail is a data exit (hostnames, paths, template names). Keep `SMTP_TO` on a small operator list.
Sending is not an audit `event_id`; success and failure are ordinary structured logs. PostgreSQL
holds an at-most-once outbox row so a backend restart does not resend.
