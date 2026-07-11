# API reference

The JSON API lives under `/api/*` and is guarded by the session cookie (see
[Configuration → Authentication](CONFIGURATION.md#authentication-oidcbff)). The examples
below assume a cookie jar `jar.txt` populated by a real login, or
[auth-disabled dev mode](CONFIGURATION.md#authentication-oidcbff) for headless use.

Authorization per endpoint follows the three roles: reads need `viewer`, running scans and
config writes need `operator`, deletes need `admin`.

## Scans

A scan must name a stored **target** (`target_id`) or an ad-hoc `spec`; every host it targets
has to fall inside an approved target record (the [scope guardrail](#scope-guardrail)). Create
a target first (see [Config](#config-targets--template-sets)), then:

```sh
# start a scan from a stored target
curl -sb jar.txt -X POST localhost:8080/api/scans \
  -H 'content-type: application/json' -d '{"target_id":"<id>"}'   # => {"scan_id":"..."}
# check scan state (queued → running → complete)
curl -sb jar.txt localhost:8080/api/scans/<scan_id>
# occurrences observed by one scan (paginated envelope: {items,total,limit,offset})
curl -sb jar.txt "localhost:8080/api/scans/<scan_id>/findings" | jq
```

An empty body (or targets outside every approved target) is rejected `400` — there is no
implicit default scan, so the scanner can't be fat-fingered at out-of-scope assets.

Override the stored target/templates with an ad-hoc spec (note the `spec` wrapper). Every host
in `spec.targets` must still fall inside an approved target — here `scanme.sh` must already
exist as a target host, or the request is rejected `400` (see [scope guardrail](#scope-guardrail)):

```sh
curl -sb jar.txt -X POST localhost:8080/api/scans -H 'content-type: application/json' -d '{
  "spec": {
    "targets": ["scanme.sh"],
    "templates": {"severities": ["info","low"], "tags": ["tech"]},
    "options": {"rate_limit": 150, "concurrency": 25, "timeout_sec": 600}
  }
}'
```

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

`GET /api/findings` supports server-side filtering + pagination: `q` (name/template substring),
`severity` (comma-separated, any-of, matched against the effective severity), `host`
(substring), `cve` (substring), `tag` (exact), `disposition` (exact), `state` (exact effective
state), plus `target_id`, `limit`, `offset`. CVE ids and tags are promoted to indexed columns
so these filters are cheap.

```sh
curl -sb jar.txt "localhost:8080/api/findings?severity=critical,high&state=new&limit=50" | jq
```

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

## Schedules

A schedule runs a target (+ optional template set) on a **cron** cadence, unattended. A backend
ticker wakes each minute and dispatches the schedules whose next fire time has arrived — through
the same path as an ad-hoc scan, so scheduled scans are tracked in the finding lifecycle exactly
like manual ones (a scheduled scan carries `source: "schedule"`). Postgres is the source of
truth: enable/disable and the next-run time persist across restarts, and a run missed while the
backend was down fires once on the next tick, then reschedules forward.

```sh
# create a schedule: nightly scan of a target at 03:00 (5-field cron; also
# accepts @hourly/@daily/… and "@every 30m")
curl -sb jar.txt -X POST localhost:8080/api/schedules -H 'content-type: application/json' -d '{
  "name": "nightly-prod",
  "target_id": "<target_id>",
  "template_set_id": "<template_set_id>",
  "cron": "0 3 * * *",
  "enabled": true
}'
# list schedules (each shows next_run_at / last_run_at / last_scan_id)
curl -sb jar.txt localhost:8080/api/schedules | jq
# pause a schedule (edit) — enabled:false clears its next run
curl -sb jar.txt -X PUT localhost:8080/api/schedules/<id> -H 'content-type: application/json' \
  -d '{"name":"nightly-prod","target_id":"<target_id>","cron":"0 3 * * *","enabled":false}'
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
# launch a scan from stored config
curl -sb jar.txt -X POST localhost:8080/api/scans -d '{"target_id":"<id>","template_set_id":"<id>"}'
```

Both resources support the full REST set: `GET|POST /api/targets`,
`GET|PUT|DELETE /api/targets/{id}` (and likewise `/api/template-sets`). Deleting a target or
template set nulls the link on past scans but never deletes scan history.

## Scope guardrail

A scan may only target hosts that fall inside an **approved target record** — the union of all
your targets' hosts is the allowlist. This is the most important guardrail: for an active
scanner, accidentally aiming at out-of-scope or third-party assets is the difference between a
tool and an incident. Scans launched from a stored `target_id` (and schedules) are in scope by
construction; ad-hoc `spec` scans are validated and matched against the allowlist before
dispatch, and anything outside it is rejected `400` before the scanner is ever contacted.

Matching is **host-granular and never resolves DNS**: exact hostname (no wildcard, so
`example.com` does **not** authorize `sub.example.com`), IP-in-CIDR, and CIDR-within-CIDR; ports
and URL paths are ignored (the asset is the host). It **fails closed** — with no approved
targets, every scan is rejected until you add one.

## Audit log

Every mutating API call (create / update / delete / scan-dispatch / triage) emits one structured
**`event=audit`** line to **stdout** — there is no audit table and no in-app audit screen by
design. In the cloud the container's stdout is already shipped to a log aggregator (CloudWatch,
Azure Log Analytics, GCP Cloud Logging, Loki, …); that system owns retention, indexing, and
querying, and because the trail lives off the app database a DB compromise can't rewrite it.

Each event carries the actor (`actor_subject` / `actor_email`), an `event_id`, the fine-grained
`action`, the object (`object_type` / `object_id`), `method`, `path`, `status`, and
`duration_ms`. `event_id` is a small, stable vocabulary to build detections on:

| `event_id` | emitted when |
|---|---|
| `access_denied` | a mutating call is rejected by authorization (HTTP 403) |
| `config_changed` | a target, template set, or schedule is created / updated / deleted |
| `scan_dispatched` | a scan is submitted (ad-hoc) or a schedule is run |
| `finding_triaged` | a finding's disposition or severity recast changes |

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
