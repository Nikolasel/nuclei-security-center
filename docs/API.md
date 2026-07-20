# API reference

The JSON API lives under `/api/*`. Interactive callers authenticate with the session cookie
(see [Configuration → Authentication](CONFIGURATION.md#authentication-oidcbff)); headless
automation authenticates with a **service-account token** presented as
`Authorization: Bearer <token>` (see [Service accounts](#service-accounts)). The examples
below assume a cookie jar `jar.txt` populated by a real login, or
[auth-disabled dev mode](CONFIGURATION.md#authentication-oidcbff) for headless use.

Authorization per endpoint follows the three roles: reads need `viewer`, running scans and
config writes need `operator`, deletes need `admin`.

## Scans

A scan is launched by selecting a **scan policy** (`scan_policy_id`) — the central, reusable
scan configuration that carries the target, template set, and execution knobs (see
[Scan policies](#config-scan-policies)). There is no ad-hoc target/spec path: every scan names
a policy, so scope is guaranteed by construction (a policy always references a stored target).
Create a policy first, then:

```sh
# start a scan from a scan policy
curl -sb jar.txt -X POST localhost:8080/api/scans \
  -H 'content-type: application/json' -d '{"scan_policy_id":"<id>"}'   # => {"scan_id":"..."}
# check scan state (queued → running → complete)
curl -sb jar.txt localhost:8080/api/scans/<scan_id>
# occurrences observed by one scan (paginated envelope: {items,total,limit,offset})
curl -sb jar.txt "localhost:8080/api/scans/<scan_id>/findings" | jq
```

Each scan record carries the `scan_policy_id` / `scan_policy_name` it ran, plus the
`target_id` / `target_name` / `target_host_count` the policy resolved to (the target fields are
absent once the target or policy has been deleted — scan history survives either way), so a
queued/running scan is identifiable before any findings appear. `target_host_count` (and a
target's own `host_count` from [Config](#config-targets--template-sets)) is the real
address-range size, expanding any CIDR entry rather than counting it as one array element — a
target scoped to `10.0.0.0/24` reports 256, not 1.

While a scan is **running**, `GET /api/scans` and `GET /api/scans/{id}` include a live
`progress` object — `{percent, requests, total, hosts, rps, matched}` — parsed from Nuclei's
periodic `-stats-json` output on the scanner node (#66). It's ephemeral: the backend caches the
latest snapshot in memory only while the scan runs (nothing is persisted), so it disappears once
the scan reaches a terminal state. The SPA renders it as a progress bar. It may be absent briefly
at the very start, before the node reports its first stats. It's an aggregate across every host
in the scan, not a per-host breakdown — Nuclei's own stats-json has no concept of "current host"
since it works multiple hosts concurrently rather than one at a time.

A scan that **fails after finding something** — most commonly a `timeout_sec` kill on a large
multi-host scan — still ingests whatever Nuclei had already written to its JSONL output before
being killed, rather than discarding it. The scan record stays `failed` (it's honest that the run
didn't finish), but findings from hosts that completed before the timeout aren't lost.

An empty body (or an unknown `scan_policy_id`) is rejected `400` — there is no implicit default
scan, and because a policy always references a stored target, a scan can't be pointed at an
out-of-scope asset.

**Stop / delete.** A queued or running scan can be stopped (operator); the backend marks it
`cancelled` and best-effort signals the node to abort the run. A terminal scan can be deleted
(admin) — its findings occurrences cascade away and the archived raw output is purged
best-effort; a running scan must be cancelled first (`409`).

```sh
# stop a queued/running scan (operator). 409 if it's already terminal, 404 if unknown.
curl -sb jar.txt -X POST localhost:8080/api/scans/<scan_id>/cancel   # => 204
# delete a terminal scan record (admin). 409 if it's still queued/running.
curl -sb jar.txt -X DELETE localhost:8080/api/scans/<scan_id>        # => 204
```

To tune what/how a scan runs — a different target, template selection, or execution knobs —
edit or create a [scan policy](#config-scan-policies) and select it; the scan itself takes only
a `scan_policy_id`.

## Findings lifecycle

Findings are **deduplicated** across scans and tracked over time with a **Tenable Security
Center-style** lifecycle (design rationale in
[ARCHITECTURE.md §3](ARCHITECTURE.md#3-data-model-core-tables)). `GET /api/findings` returns
the deduplicated entities (keyed on `(target, template, matched_at)`). Each has:

- a **detection state** — derived from scan observation, never stored. **Closure is
  evidence-driven — there is no manual "fixed."** The state is a function of whether the
  finding is in the target's latest completed scan and how many times it has come back after
  disappearing (`times_mitigated`):

  | Detection state | In latest scan? | Meaning |
  |---|---|---|
  | `new` | yes | first time ever observed |
  | `active` | yes | seen before, never gone |
  | `resurfaced` | yes | was mitigated, now detected again — a **regression** |
  | `mitigated` | no | previously seen; the latest scan no longer finds it (auto-closed) |
  | `previously_mitigated` | no | mitigated, came back, and is gone again — a **flapping** finding |

  `resurfaced` is to `active` what `previously_mitigated` is to `mitigated`: same current
  presence, but "…and this has disappeared before." Both need attention a clean
  `active`/`mitigated` doesn't — a regressed fix, or a vuln that keeps reappearing.
- a manual **disposition** — `none` / `false_positive` / `accepted` (Accept Risk, with an
  optional `accept_expires_at`; an expired acceptance reverts to the detection state) — and an
  optional **`recast_severity`** (Recast Risk).
- an **`effective_state`** and **`effective_severity`** overlaying the two (an `accepted` or
  `false_positive` disposition wins; otherwise you see the detection state).

`GET /api/scans/{id}/findings` returns the immutable per-scan **occurrences** instead.

```sh
# deduplicated lifecycle list (paginated + filtered)
curl -sb jar.txt "localhost:8080/api/findings" | jq
# one tracked finding + full raw Nuclei output of its latest occurrence
curl -sb jar.txt "localhost:8080/api/findings/<finding_id>" | jq
# disposition (operator) — none | false_positive | accepted (+ optional accept_expires_at)
curl -sb jar.txt -X PATCH localhost:8080/api/findings/<finding_id>/disposition \
  -H 'content-type: application/json' \
  -d '{"disposition":"accepted","note":"risk accepted for Q3","accept_expires_at":"2027-01-01T00:00:00Z"}'
# recast severity (operator) — empty severity clears the recast
curl -sb jar.txt -X PATCH localhost:8080/api/findings/<finding_id>/severity \
  -H 'content-type: application/json' -d '{"severity":"high","note":"internet-facing"}'
```

`GET /api/findings` supports server-side filtering + pagination. The filter is a **structured
condition grammar** (a ServiceNow-style condition builder in the UI), passed as one JSON
`filter` param: **OR-of-AND groups** — conditions within a group are ANDed, groups are ORed, so
it expresses e.g. *(severity is one of critical, high AND host contains scanme) OR (cve is
empty)*. Each condition is `{field, op, values}`:

| Field | Operators |
| --- | --- |
| `severity`, `state`, `disposition`, `target` | `any_of`, `none_of` |
| `name` (name/template) | `contains`, `starts_with` |
| `host` | `contains`, `not_contains`, `starts_with`, `is_empty`, `is_not_empty` |
| `cve` | `contains`, `not_contains`, `is_empty`, `is_not_empty` |
| `tag` | `any_of`, `none_of`, `is_empty`, `is_not_empty` |

Fields and operators are allowlisted (an unknown one is a `400`); every value is bound as a SQL
parameter, so a filter never concatenates user input into the query. Plus `limit`, `offset`.

```sh
# (critical OR high) AND host contains scanme  — one AND-group
FILTER='{"groups":[{"conditions":[
  {"field":"severity","op":"any_of","values":["critical","high"]},
  {"field":"host","op":"contains","values":["scanme"]}]}]}'
curl -sb jar.txt --get "localhost:8080/api/findings" --data-urlencode "filter=$FILTER" --data limit=50 | jq
```

The legacy flat params (`severity=critical,high&host=…`, repeated or comma-separated) are still
accepted when no `filter` is given — compiled into a single AND-group — so old bookmarks and API
callers keep working. Arbitrary nested parenthesized grouping (beyond OR-of-AND) remains a
possible future extension.

## Export

The deduplicated lifecycle list exports as **JSON**, **CSV**, **SARIF 2.1.0**, or **raw JSONL**
via `GET /api/findings/export?format=…`. The export takes the *same* filter params as
`/api/findings`, so you export exactly what you're looking at (unpaginated). CSV is a flat
table for spreadsheets; SARIF is a valid 2.1.0 document (deduped rules + per-finding results,
severity→level) for code-scanning / CI ingestion. The projected formats carry the lifecycle
overlay — detection state, disposition, `times_mitigated`. **Raw JSONL** instead emits the
*verbatim Nuclei output* of each finding's latest occurrence, one JSON object per line (Nuclei's
native `out.jsonl` shape) — the full request/response, curl reproducer, and classification that
the projected formats drop.

```sh
# every critical/high finding still active, as CSV
curl -sb jar.txt "localhost:8080/api/findings/export?format=csv&severity=critical,high&state=active" -o findings.csv
# the same filter as SARIF, e.g. to upload to GitHub code scanning
curl -sb jar.txt "localhost:8080/api/findings/export?format=sarif&severity=critical,high" -o findings.sarif
# raw Nuclei JSONL (verbatim scanner output) for the current view
curl -sb jar.txt "localhost:8080/api/findings/export?format=raw&severity=critical,high" -o findings.jsonl
```

Every format carries the **lifecycle finding `id`** as a shared join key — a column in CSV,
`id` in JSON, `properties.nsc_lifecycle_id` in SARIF, and `_nsc_lifecycle_id` on each raw JSONL
line (a namespaced field that doesn't collide with Nuclei's) — so a raw export joins back to the
projected triage data (and to `GET /api/findings/{id}`) on one key. The SPA offers the same four
formats from an **Export** menu on the Findings view.

## Downstream tooling (DefectDojo, etc.)

NSC deliberately doesn't ship built-in integrations for any specific downstream
vulnerability-management tool — dashboards, SLA tracking, ticketing, and remediation
workflows are explicitly out of scope (closed as "well covered by DefectDojo or a similar
VM tool downstream" — see #11, #12, #14, #16, #17, #20). `/api/findings/export` is the
general-purpose extension point: it's a normal, filterable, session-cookie-authenticated
REST endpoint, so anything downstream round-trips through NSC's existing API and the
other tool's own API — no NSC code or config coupled to one vendor.

**Worked example — DefectDojo.** DefectDojo ships a native **"Nuclei Scan"** import
parser that consumes exactly the `format=raw` shape above (Nuclei's own `out.jsonl`), so
no translation step is needed:

```sh
# 1. pull NSC's raw export for the view you want to push (same filters as /api/findings)
curl -sb jar.txt "localhost:8080/api/findings/export?format=raw&target_id=$TARGET_ID" -o findings.jsonl

# 2. hand it to DefectDojo's reimport-scan API — "reimport" (not "import") so repeat runs
#    dedupe/update within DefectDojo's own engagement instead of creating duplicates each time
curl -s "$DEFECTDOJO_URL/api/v2/reimport-scan/" \
  -H "Authorization: Token $DEFECTDOJO_API_KEY" \
  -F "scan_type=Nuclei Scan" \
  -F "product_name=$DD_PRODUCT" \
  -F "engagement_name=$DD_ENGAGEMENT" \
  -F "file=@findings.jsonl"
```

Run that as a small script — cron, CI job, whatever your team already uses for scheduled
glue — after a scan (or its schedule) completes. A few things worth being explicit about,
since none of this lives in NSC:

- **Target ↔ Product/Engagement mapping** is a decision made in the script or on the
  DefectDojo side (by name, by a lookup table, however your team organizes DefectDojo) —
  NSC has no concept of it and stores nothing DefectDojo-specific.
- **Auth uses a service-account token** — mint one with an `Authorization: Bearer` token
  scoped to `viewer` (export is a read) and revoke it independently of any human login.
  See [Service accounts](#service-accounts) below. (The session cookie still works too, but
  a token is the right fit for unattended pullers.)
- **The push is your automation's problem to make reliable**, not NSC's — retries,
  failure alerting, and backoff belong in the script/job, the same way you'd treat any
  other external integration you own.

The same pattern covers any tool that can consume one of the four export formats — the
SARIF example above for GitHub code scanning is the same idea (pull an export, push it to
the other system's API) applied to a different consumer.

## Schedules

A schedule pairs a **scan policy** with a **cron** cadence and runs it unattended (the policy
carries the target, template set, and knobs — the schedule just picks one and a cadence). A
backend ticker wakes each minute and dispatches the schedules whose next fire time has arrived —
through the same path as an ad-hoc scan, so scheduled scans are tracked in the finding lifecycle
exactly like manual ones (a scheduled scan carries `source: "schedule"`). Postgres is the source
of truth: enable/disable and the next-run time persist across restarts, and a run missed while
the backend was down fires once on the next tick, then reschedules forward.

```sh
# create a schedule: run a scan policy at 03:00 nightly (5-field cron; also
# accepts @hourly/@daily/… and "@every 30m").
curl -sb jar.txt -X POST localhost:8080/api/schedules -H 'content-type: application/json' -d '{
  "name": "nightly-prod",
  "scan_policy_id": "<scan_policy_id>",
  "cron": "0 3 * * *",
  "enabled": true
}'
# list schedules (each shows next_run_at / last_run_at / last_scan_id)
curl -sb jar.txt localhost:8080/api/schedules | jq
# pause a schedule (edit) — enabled:false clears its next run
curl -sb jar.txt -X PUT localhost:8080/api/schedules/<id> -H 'content-type: application/json' \
  -d '{"name":"nightly-prod","scan_policy_id":"<scan_policy_id>","cron":"0 3 * * *","enabled":false}'
# dispatch once now, off-schedule (leaves the cron cadence untouched)
curl -sb jar.txt -X POST localhost:8080/api/schedules/<id>/run     # => {"scan_id":"..."}
curl -sb jar.txt -X DELETE localhost:8080/api/schedules/<id>       # remove
```

Reads need `viewer`; create/edit/run need `operator`; delete needs `admin`. The SPA exposes all
of this on the **Schedules** page (cron presets, enable/disable toggle, run-now).

## Config: targets & template sets

Reusable **targets** (a named host allowlist) and **template sets** (severity/tag/path filters +
optional pinned git ref) to launch scans from:

```sh
# create a target (the hosts list is the scope allowlist)
curl -sb jar.txt -X POST localhost:8080/api/targets -d '{"name":"prod-web","hosts":["scanme.sh"],"tags":["prod"]}'
# create a template set
curl -sb jar.txt -X POST localhost:8080/api/template-sets -d '{"name":"info","severities":["info","low"]}'
# ...then bundle them into a scan policy (see Config: scan policies below)
```

A target's response carries a derived `host_count`: each hostname/IP/URL entry counts as one,
but a CIDR entry expands to its full address-range size (`"hosts":["10.0.0.0/24"]` reports
`"host_count":256`), so the scope really covered is visible before running a scan against it.

Both resources support the full REST set: `GET|POST /api/targets`,
`GET|PUT|DELETE /api/targets/{id}` (and likewise `/api/template-sets`). Deleting a target or
template set nulls the link on past scans but never deletes scan history. A target still in use
by a scan policy can't be deleted out from under it — the policy references it (see below).

## Config: scan policies

A **scan policy** is the central, reusable **scan configuration** — it bundles *everything* a
scan needs: the **target** (`target_id`, required — the scope), an optional **template set**
(`template_set_id`, omitted = all templates), and Nuclei's execution knobs
(`rate_limit` / `concurrency` / `timeout_sec` / `max_host_error`). **Every scan and schedule is
launched by selecting a policy** — the scan/schedule body carries only a `scan_policy_id`. Each
knob is optional: a `null` (omitted) field means "use the built-in default" (rate `150` /
concurrency `25` / timeout `600`s / `max_host_error` Nuclei's own `30`), so a policy can tune
just one knob and leave the rest alone.

`max_host_error` is Nuclei's `-max-host-error`: how many errors a single host may accumulate
(across every protocol, not per port) before Nuclei abandons it for the rest of the run —
silently skipping executors that hadn't run yet (e.g. the SSL/TLS pass). Raising it, and/or
lowering the rate, is the fix for scanning fragile devices that trip the default of 30 on HTTP
alone.

```sh
# a policy for a fragile device: which target/templates + slow it down, tolerate more host errors
curl -sb jar.txt -X POST localhost:8080/api/scan-policies -H 'content-type: application/json' -d '{
  "name": "fragile-device",
  "target_id": "<target_id>",
  "template_set_id": "<template_set_id>",
  "rate_limit": 20,
  "concurrency": 5,
  "max_host_error": 100
}'
# launch a scan with it
curl -sb jar.txt -X POST localhost:8080/api/scans -d '{"scan_policy_id":"<id>"}'
```

Full REST set: `GET|POST /api/scan-policies`, `GET|PUT|DELETE /api/scan-policies/{id}` (reads
`viewer`, create/edit `operator`, delete `admin`, audited as `config_changed`). The
`target_id`/`template_set_id` must reference existing rows (`400` otherwise). Deleting a policy
nulls the link on past scans (history survives) and **cascades away any schedules built on it**;
deleting a policy's target cascades the policy away too.

## Scanner nodes

The **scanner node registry** (#22) is the DB-backed list of nodes the backend dispatches to. A
scan runs on the node whose `cidrs` contain its target's IP; a node with no CIDRs is a **catch-all**
for hostname targets and IPs matching no other node. Reads need `viewer`; create/update/delete need
`admin` and are audited as config changes.

```sh
# list nodes (each includes derived health: healthy / last_seen / nuclei_version)
curl -sb jar.txt localhost:8080/api/nodes
# add a node serving a CIDR range
curl -sb jar.txt -X POST localhost:8080/api/nodes \
  -d '{"name":"corp","endpoint":"http://scanner-corp:8081","token":"<bearer>","cidrs":["10.0.0.0/8"],"tags":["corp"]}'
```

- `token` is **write-only** — required on create, never returned by `GET`. On update, **leave it
  blank to keep the stored one** (so other fields can be edited without re-supplying the secret).
- CIDRs must **not overlap** another node (`400`), so a target's IP maps to exactly one node. A scan
  whose targets span two nodes is rejected. Deleting the **last** catch-all node is refused (`409`),
  so hostname targets always have somewhere to dispatch.
- **Per-node mTLS (#26):** optional `tls_server_ca`, `tls_client_cert`, `tls_client_key` upgrade the
  backend→node transport to mutual TLS for a node in an untrusted segment (point its `endpoint` at
  `https://…`). The CA + client cert are public and returned on `GET`; `tls_client_key` is a
  **write-only secret** like `token` (never returned; blank on update keeps the stored key). On
  create the client cert + key must be supplied together; bad PEM / a mismatched pair is a `400`.
  See [CONFIGURATION.md](CONFIGURATION.md#service-auth-tls--mtls).
- Endpoints: `GET|POST /api/nodes`, `GET|PUT|DELETE /api/nodes/{id}`.
- **Health (#98):** the backend polls each node's `GET /v1/capabilities` (`nuclei_version`) every
  `NODE_HEALTH_INTERVAL` to derive liveness; `healthy` is `null` until the first poll. When a node
  is unhealthy, `health_error` carries the last poll failure (e.g. `capabilities: 401 Unauthorized`
  for a wrong token vs. a connection error for an unreachable node), so the cause is visible without
  reading server logs. A scan whose matching node is known-unhealthy fails fast with a clear error.
  Config (`SCANNER_URL`/`SCAN_ZONES`) seeds this registry on first boot only —
  see [CONFIGURATION.md](CONFIGURATION.md#scanner-node-registry).

## Scope guardrail

A scan may only target hosts that fall inside an **approved target record**. This is the most
important guardrail: for an active scanner, accidentally aiming at out-of-scope or third-party
assets is the difference between a tool and an incident. Every scan is launched from a **scan
policy**, and a policy always references a stored target — so a scan is **in scope by
construction**: there is no path to name a host that isn't already an approved target. (Targets
remain a first-class resource so `host_count` and the allowlist stay meaningful, and so several
policies can reuse the same approved scope.)

Target hosts themselves are still validated as hostnames/IPs/CIDRs/URLs when a target is
created. The allowlist **fails closed** — with no approved targets there is nothing to build a
policy from, so no scan can run until you add one.

## Service accounts

Service accounts are NSC-local identities for **headless/automation** access — a cron job or CI
step pulling `/api/findings/export`, for instance — so a script doesn't have to impersonate a
human login. They are additive to, not a replacement for, the OIDC/BFF session cookie, which
stays the only path for interactive users.

Each account is scoped to **one role** (the same `viewer` / `operator` / `admin` RBAC as the
session cookie) and authenticates with a bearer token. Managing them is **admin-only**. The token
is shown **once**, at creation and on rotation — only its SHA-256 hash is stored, so a lost token
is rotated, never recovered.

Admins manage these from the **Service Accounts** page in the UI (the nav entry appears for admins
only), which is the normal way to mint, rotate, and revoke a token — the endpoints below are the
same surface for scripting it.

```sh
# Create (admin). ttl_days is optional: omitted => 90 days; 0 => no expiry.
curl -sb jar.txt -X POST localhost:8080/api/service-accounts \
  -H 'Content-Type: application/json' \
  -d '{"name":"defectdojo-export","role":"viewer","ttl_days":90}'
# => 201 { "id":"…", "name":"defectdojo-export", "role":"viewer",
#          "token_prefix":"nsc_AbCdEfG", "expires_at":"…",
#          "token":"nsc_…"  }   <-- copy the token now; it is never shown again

# Use it — no cookie, just the bearer token:
curl -H "Authorization: Bearer $NSC_TOKEN" \
  "localhost:8080/api/findings/export?format=raw&target_id=$TARGET_ID"

# List (admin) — never returns tokens, only prefixes + last_used_at.
curl -sb jar.txt localhost:8080/api/service-accounts

# Rotate (admin) — mints a new token and invalidates the old one immediately.
curl -sb jar.txt -X POST localhost:8080/api/service-accounts/$ID/rotate

# Revoke (admin) — deletes the account; the token stops working at once.
curl -sb jar.txt -X DELETE localhost:8080/api/service-accounts/$ID
```

| Method & path | Role | Purpose |
|---|---|---|
| `GET /api/service-accounts` | admin | list accounts (no tokens) |
| `POST /api/service-accounts` | admin | create; returns the token once |
| `POST /api/service-accounts/{id}/rotate` | admin | mint a new token, invalidate the old |
| `DELETE /api/service-accounts/{id}` | admin | revoke (delete) the account |

A bad or expired bearer token is rejected with `401` — it never silently falls through to cookie
auth. Token calls appear in the [audit log](#audit-log) as `actor_type=service_account`.

## Audit log

Every mutating API call (create / update / delete / scan-dispatch / triage) emits one structured
**`event=audit`** line to **stdout** — there is no audit table and no in-app audit screen by
design. In the cloud the container's stdout is already shipped to a log aggregator (CloudWatch,
Azure Log Analytics, GCP Cloud Logging, Loki, …); that system owns retention, indexing, and
querying, and because the trail lives off the app database a DB compromise can't rewrite it.

Each event carries the actor (`actor_subject` / `actor_email` / `actor_type`), an `event_id`, the
fine-grained `action`, the object (`object_type` / `object_id`), `method`, `path`, `status`, and
`duration_ms`. `actor_type` is `service_account` for token callers (their `actor_subject` is
`svc:<name>`) and `user` for interactive logins, so automation is never conflated with a person.
`event_id` is a small, stable vocabulary to build detections on:

| `event_id` | emitted when |
|---|---|
| `access_denied` | a mutating call is rejected by authorization (HTTP 403) |
| `config_changed` | a target, template set, or schedule is created / updated / deleted |
| `scan_dispatched` | a scan is submitted (ad-hoc) or a schedule is run |
| `finding_triaged` | a finding's disposition or severity recast changes |
| `service_account_changed` | a service-account token is created / rotated / revoked |

All audit events log at **INFO** — a denial is authorization working as intended, not a fault —
so alerting keys off `event_id` / `status`, not the log level. Tail them locally with:

```sh
docker compose logs -f backend | grep '"event":"audit"'
```

## Raw scan-output archive

Each scan's verbatim Nuclei output (`out.jsonl`) is archived to an S3-compatible bucket — MinIO
in the Compose stack, any S3 API in the cloud. Postgres remains the system of record for the
projected findings; the bucket holds the bulky, write-once evidence. Archiving is
**best-effort**: if the upload fails, the scan still succeeds (the findings are already ingested)
and it's logged, not fatal.

```sh
# download a completed scan's archive (streamed back through the backend, behind your session)
curl -sb jar.txt localhost:8080/api/scans/<scan-id>/raw -o scan.jsonl
```

The scan-detail page shows a **Download raw output** link once the archive exists (`has_raw`).
With `S3_ENDPOINT` unset the feature is off and the endpoint returns 404. Object-store
configuration is in [Configuration](CONFIGURATION.md#object-storage).
