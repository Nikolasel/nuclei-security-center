# API reference

The JSON API lives under `/api/*`. Interactive callers authenticate with the session cookie
(see [Administration → Authentication](ADMIN_GUIDE.md#3-authentication-service-accounts-and-transport-security)); headless
automation authenticates with a **service-account token** presented as
`Authorization: Bearer $NSC_TOKEN` (see [Service accounts](#service-accounts)). The examples
below assume a cookie jar `jar.txt` populated by a real login, or
[auth-disabled dev mode](ADMIN_GUIDE.md#authentication-and-sessions) for headless use.

Authorization per endpoint follows the three roles: reads need `viewer`, running scans and
config writes need `operator`, deletes need `admin`.

## Scans

A scan is launched by selecting a **scan policy** (`scan_policy_id`) — the central, reusable
template and execution configuration — and an approved **target** (`target_id`; see
[Scan policies](#config-scan-policies)). There is no ad-hoc host/spec path: every scan names a
stored target, so scope is guaranteed by construction. Create a policy and target first, then:

```sh
# start a scan using a policy against an approved target
curl -sb jar.txt -X POST localhost:8080/api/scans \
  -H 'content-type: application/json' \
  -d '{"scan_policy_id":"<policy_id>","target_id":"<target_id>"}'   # => {"scan_id":"..."}
# check scan state (queued → running → complete)
curl -sb jar.txt localhost:8080/api/scans/<scan_id>
# occurrences observed by one scan (paginated envelope: {items,total,limit,offset})
curl -sb jar.txt "localhost:8080/api/scans/<scan_id>/findings" | jq
```

Each scan record carries the `scan_policy_id` / `scan_policy_name` it ran, the
`template_set_id` / `template_set_name` selected at dispatch, plus the `target_id` /
`target_name` / `target_host_count` selected at dispatch (linked fields are absent once their
source row has been deleted — scan history survives), so a queued/running scan is identifiable
before any findings appear. `target_host_count` (and a
target's own `host_count` from [Config](#config-targets--template-sets)) is the real
address-range size, expanding any CIDR entry rather than counting it as one array element — a
target scoped to `10.0.0.0/24` reports 256, not 1. `templates_commit` is recorded when the scan
is queued: together with the concrete `template_ids` in its stored spec, it identifies exactly
which content-addressed catalog bundle the node ran.
`skipped_finding_count` reports source records that were proven malformed and skipped during
backend ingest; database, transaction, schema, and other operational ingest failures remain
scan-fatal. A complete scan with a non-zero count is known-incomplete and does not contribute
negative mitigation evidence; exact findings that were ingested still provide positive evidence.

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

An empty body, missing ID, or unknown `scan_policy_id` / `target_id` is rejected `400` — there is
no implicit default scan and no path to submit an arbitrary host.

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

To tune how a scan runs, edit or create a [scan policy](#config-scan-policies). Select the target
separately at launch, so the same policy can be reused across approved scopes.

**Scan bundles — export / import (#136).** `GET /api/scans/{id}/export?format=json|zip` (viewer)
downloads a complete, self-contained, versioned manifest of one scan **result**: the scan record
(`state`, timestamps, `source`, `discovered_targets`, `covered_endpoints`, resolved
`template_ids` + `templates_commit`, and the verbatim dispatch `spec`), the resolved config that
produced it (target / template-set / scan-policy snapshots plus the reference ids on the
exporting instance), and every immutable **occurrence** with its preserved Nuclei raw JSON.
Like a scan-results file (a Nessus `.ness` import), the bundle carries **the scan's data, not
the exporter's globally deduplicated finding lifecycle** — analyst dispositions/recasts,
first/last-seen, and mitigation counters are never exported. `format=zip` wraps the same
document as `manifest.json` inside a zip archive.

`POST /api/scans/import?conflict=error|duplicate&coverage=ignore|trust` (operator, audited
`scan_imported`) recreates the scan on this instance and ingests its findings through the normal
lifecycle path, so the destination **re-derives its own lifecycle** (dedup identity,
first/last-seen, mitigation state) from the results exactly as if it had scanned the target
itself. The dedup identity is
**recomputed from the verbatim raw payload** — never trusted from the manifest — and occurrence
scope follows the resolved destination target. References (target / template set / scan policy /
node / schedule) that don't exist here **fall back to NULL** and are listed in the response's
`fallbacks`; a missing entity never fails the import (fail-soft on references, fail-hard on the
bundle itself). An in-flight (queued/running) export imports as `failed`. A destination
analyst's overlays are never touched (they were never exported). The manifest's
`covered_endpoints` and `coverage_warning` are exporter-authored trace claims. With the default
`coverage=ignore`, they are discarded, the destination stores coverage as unknown (`NULL`), and
a coverage-only bundle cannot mitigate an existing finding. `coverage=trust` is an explicit
operator opt-in: exact imported endpoint pairs are persisted and may mark matching existing
findings mitigated, using the same scope and skipped-record rules as a completed local scan.
In trust mode, each imported coverage pair must include a non-empty `template_id` and `endpoint`
(`400` otherwise).
Exact findings carried by a completed bundle always provide positive evidence through normal
occurrence ingestion. `discovered_targets` is retained for scan-detail display only and never
contributes to mitigation evidence. The default conflict policy
`error` returns **409** when the exported scan id already exists locally; `conflict=duplicate`
imports under a fresh id instead. A bundle must be a format/version this backend understands
and must validate (`400` otherwise) — including a `scan.source` and no future-dated
timestamps. Zip bundles are sniffed by the `PK` magic, must contain exactly one
`manifest.json`, and are extracted with a 512 MiB upload ceiling (decompressed manifest
capped at 128 MiB).

```sh
# download the manifest for one scan (viewer)
curl -sb jar.txt "localhost:8080/api/scans/<scan_id>/export" -o bundle.nsc-bundle.json
# the same document zipped
curl -sb jar.txt "localhost:8080/api/scans/<scan_id>/export?format=zip" -o bundle.nsc-bundle.zip
# recreate the scan + results here (operator); 409 if the id already exists
curl -sb jar.txt -X POST -H 'content-type: application/octet-stream' \
  --data-binary @bundle.nsc-bundle.zip "localhost:8080/api/scans/import" | jq
```

## Findings lifecycle

Findings are **deduplicated** across scans and tracked over time with a **Tenable Security
Center-style** lifecycle (design rationale in
[ARCHITECTURE.md §3](ARCHITECTURE.md#3-data-model-core-tables)). `GET /api/findings` returns
the globally deduplicated entities (keyed on `(template, matched_at, stable result variant)`;
scan and target are occurrence provenance). The stable variant uses matcher/extractor names and
canonicalized extracted results, so a template can track TLS 1.2 and TLS 1.3 independently
without hashing volatile request/response/timestamp data. Extracted values are deliberately part
of identity even when matcher/extractor names are absent: some multi-result templates (including
TLS-version results) expose no other stable discriminator. Consequently, a template whose
extracted value is inherently volatile will create distinct lifecycle entities; template authors
should give such results a stable matcher/extractor or avoid volatile extraction when lifecycle
continuity is desired. Each has:

- a **detection state** — derived from scan observation, never stored. **Closure is
  evidence-driven — there is no manual "fixed."** The state is a function of whether the
  finding is in the latest completed scan, across scopes that have observed the global result,
  whose request trace proves the exact template id + normalized host:port pair, and how many
  times it has come back after disappearing
  (`times_mitigated`). A scan using a narrower template set, or one whose Nuclei request trace
  shows only another port, another template, or a failed/unreachable request, is not mitigation
  evidence. `covered_endpoints: null` means telemetry is unavailable (including legacy scans)
  and fails closed; `[]` means the trace was read successfully but no template/endpoint pair
  completed successfully. `coverage_warning`, when present, explains skipped or unavailable
  trace evidence and is shown on scan detail. Lifecycle findings also expose
  `auto_mitigation_eligible`: `false` means `matched_at` has no normalizable network
  host:port (for example a `file`/`code` result), so scan absence deliberately cannot close
  that finding and the UI labels the limitation:

  | Detection state | In latest covering scan? | Meaning |
  |---|---|---|
  | `new` | yes | first time ever observed |
  | `active` | yes | seen before, never gone |
  | `resurfaced` | yes | was mitigated, now detected again — a **regression** |
  | `mitigated` | no | previously seen; the latest scan no longer finds it (auto-closed) |
  | `previously_mitigated` | no | mitigated, came back, and is gone again — a **flapping** finding |

  `resurfaced` is to `active` what `previously_mitigated` is to `mitigated`: same current
  presence, but "…and this has disappeared before." Both need attention a clean
  `active`/`mitigated` doesn't — a regressed fix, or a vuln that keeps reappearing.
  Scan pointers use stable scan chronology (`scans.created_at`, then id), even when scans
  finish out of order. The corresponding `_at` fields retain when the earliest/latest
  qualifying result was ingested; a late-finishing older scan can therefore become
  `first_seen_scan` without moving `first_seen_at` backward.
- a manual **disposition** — `none` / `false_positive` / `accepted` (Accept Risk, with an
  optional `accept_expires_at`; an expired acceptance reverts to the detection state) — and an
  optional **`recast_severity`** (Recast Risk).
- an **`effective_state`** and **`effective_severity`** overlaying the two (an `accepted` or
  `false_positive` disposition wins; otherwise you see the detection state).

`GET /api/scans/{id}/findings` returns the immutable per-scan **occurrences** instead. Each row
has its own exact detail at `GET /api/occurrences/{occurrence_id}`. The scan UI opens that route
directly; it never substitutes the lifecycle's latest occurrence.

```sh
# deduplicated lifecycle list (paginated + filtered)
curl -sb jar.txt "localhost:8080/api/findings" | jq
# one tracked finding + full raw Nuclei output of its latest occurrence
curl -sb jar.txt "localhost:8080/api/findings/<finding_id>" | jq
# one exact immutable result from a concrete scan
curl -sb jar.txt "localhost:8080/api/occurrences/<occurrence_id>" | jq
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
parameter, so a filter never concatenates user input into the query. `target none_of` also
includes ad-hoc-only findings because they have no occurrence belonging to an excluded target.
Plus `limit`, `offset`.

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
overlay — detection state, disposition, `times_mitigated`, and all contributing `target_ids`.
**Raw JSONL** instead emits the
preserved Nuclei output of each finding's latest occurrence, one JSON object per line (Nuclei's
native `out.jsonl` shape) — the full request/response, curl reproducer, and classification that
the projected formats drop. PostgreSQL-backed exports replace invalid UTF-8 with U+FFFD; the
per-scan object-storage archive remains the byte-exact scanner output.

```sh
# every critical/high finding still active, as CSV
curl -sb jar.txt "localhost:8080/api/findings/export?format=csv&severity=critical,high&state=active" -o findings.csv
# the same filter as SARIF, e.g. to upload to GitHub code scanning
curl -sb jar.txt "localhost:8080/api/findings/export?format=sarif&severity=critical,high" -o findings.sarif
# raw Nuclei JSONL for the current lifecycle view
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

A schedule pairs a **scan policy** and approved **target** with a **cron** cadence and runs them
unattended. The policy supplies the template set and execution knobs; the schedule supplies the
target and cadence. A backend ticker wakes each minute and dispatches due schedules —
through the same path as an ad-hoc scan, so scheduled scans are tracked in the finding lifecycle
exactly like manual ones (a scheduled scan carries `source: "schedule"`). Postgres is the source
of truth: enable/disable and the next-run time persist across restarts, and a run missed while
the backend was down fires once on the next tick, then reschedules forward.

```sh
# create a schedule: run a policy against a target at 03:00 nightly (5-field cron; also
# accepts @hourly/@daily/… and "@every 30m").
curl -sb jar.txt -X POST localhost:8080/api/schedules -H 'content-type: application/json' -d '{
  "name": "nightly-prod",
  "scan_policy_id": "<scan_policy_id>",
  "target_id": "<target_id>",
  "cron": "0 3 * * *",
  "enabled": true
}'
# list schedules (each shows next_run_at / last_run_at / last_scan_id)
curl -sb jar.txt localhost:8080/api/schedules | jq
# pause a schedule (edit) — enabled:false clears its next run
curl -sb jar.txt -X PUT localhost:8080/api/schedules/<id> -H 'content-type: application/json' \
  -d '{"name":"nightly-prod","scan_policy_id":"<scan_policy_id>","target_id":"<target_id>","cron":"0 3 * * *","enabled":false}'
# dispatch once now, off-schedule (leaves the cron cadence untouched)
curl -sb jar.txt -X POST localhost:8080/api/schedules/<id>/run     # => {"scan_id":"..."}
curl -sb jar.txt -X DELETE localhost:8080/api/schedules/<id>       # remove
```

Reads need `viewer`; create/edit/run need `operator`; delete needs `admin`. The SPA exposes all
of this on the **Schedules** page (cron presets, enable/disable toggle, run-now).

## Config: targets & template sets

Reusable **targets** (a named host allowlist) and **template sets** (explicit selections from the
template catalog) to launch scans from:

```sh
# create a target (the hosts list is the scope allowlist)
curl -sb jar.txt -X POST localhost:8080/api/targets -d '{"name":"prod-web","hosts":["scanme.sh"],"tags":["prod"]}'
# create an exact template set, then select its members (see below)
curl -sb jar.txt -X POST localhost:8080/api/template-sets -d '{"name":"critical-web","mode":"exact"}'
# ...then bundle them into a scan policy (see Config: scan policies below)
```

A target's response carries a derived `host_count`: each hostname/IP/URL entry counts as one,
but a CIDR entry expands to its full address-range size (`"hosts":["10.0.0.0/24"]` reports
`"host_count":256`), so the scope really covered is visible before running a scan against it.

Both resources support the full REST set: `GET|POST /api/targets`,
`GET|PUT|DELETE /api/targets/{id}` (and likewise `/api/template-sets`). Deleting a target or
template set nulls the link on past scans but never deletes scan history. Deleting a target also
cascades its future schedules; reusable scan policies are unaffected.

### Template-set membership

A template set has an explicit `mode`: `exact` stores individual catalog template IDs, `all`
resolves every active catalog template at scan time, and `exclude` resolves every active template
except its stored exclusions:

```sh
# set a set's membership to exactly these catalog template ids (the editor's "save")
curl -sb jar.txt -X PUT localhost:8080/api/template-sets/<set_id>/members \
  -H 'content-type: application/json' -d '{"template_ids":["CVE-2021-44228","my-custom-check"]}'
# add ids (idempotent); remove one
curl -sb jar.txt -X POST   localhost:8080/api/template-sets/<set_id>/members -d '{"template_ids":["tech-detect"]}'
curl -sb jar.txt -X DELETE localhost:8080/api/template-sets/<set_id>/members/tech-detect
# list a set's member templates (catalog rows, yaml omitted)
curl -sb jar.txt localhost:8080/api/template-sets/<set_id>/members
# replace the exclusions for an exclude-mode set (empty list clears them)
curl -sb jar.txt -X PUT localhost:8080/api/template-sets/<set_id>/exclusions \
  -H 'content-type: application/json' -d '{"template_ids":["noisy-template","incompatible-check"]}'
# list excluded catalog templates (yaml omitted)
curl -sb jar.txt localhost:8080/api/template-sets/<set_id>/exclusions
```

A template set reports `mode` and a live `member_count`. For an exact set, the count is its stored
membership; for `all`, it is the current active-catalog size; for `exclude`, it is the active-catalog
size after exclusions. An exclude set also reports `exclusion_count`; the exclusions endpoint
returns the catalog rows and the editor displays their IDs. The old top-level
`git_ref` / `severities` / `tags` / `paths` fields and their compatibility/conversion path are no
longer part of the table or API contract.

Reads are `viewer`; membership edits are `operator`, audited as `config_changed`
(`template_set.members_replace` / `_add` / `_remove`). An unknown `template_id` is a `400`; an
unknown set is a `404`. Exclusion replacement is also an operator-only audited config change
(`template_set.exclusions_replace`), and exact/all sets return `409` for exclusion reads/writes.
Direct membership edits on an all/exclude set return `409` because those modes have no stored member
rows. For `PUT /api/template-sets/{id}`, omitting `excluded_template_ids` preserves the existing
exclude-mode exclusions; sending an empty list clears them. The field is only valid with
`mode=exclude`.
The dedicated exclusions endpoint is the unambiguous replacement operation.
Dispatch resolves every set to concrete `template_ids`; empty exact sets and exclude sets whose
active catalog is fully excluded fail closed. A set containing a tombstoned/unavailable exact
template also fails until its selection is updated.

## Template catalog

The backend mirrors the upstream Nuclei template catalog into Postgres (managed by the
`TemplateSyncer`, #85) and lets you add **custom** templates alongside it. Every template is
keyed by its Nuclei `id`; `source` is `upstream` or `custom`.

For the UI-based operational workflow, see
[Administration → Template catalog and custom templates](ADMIN_GUIDE.md#template-catalog-and-custom-templates).

```sh
# browse/search newest-ingested CVE templates via their canonical tag (paginated)
curl -sb jar.txt 'localhost:8080/api/templates?tag=cve&sort=inserted&limit=50&offset=0'
# return every id matching the same filters (used by "select all matching")
curl -sb jar.txt 'localhost:8080/api/templates/ids?severity=critical&tag=rce&q=struts'
# one template incl. its verbatim YAML body
curl -sb jar.txt localhost:8080/api/templates/CVE-2021-44228
# add a custom template — the request body is raw YAML, not JSON
curl -sb jar.txt -X POST localhost:8080/api/templates --data-binary @my-check.yaml
# replace a custom template (the id inside the YAML must equal the URL id)
curl -sb jar.txt -X PUT localhost:8080/api/templates/my-custom-check --data-binary @my-check.yaml
# delete a custom template
curl -sb jar.txt -X DELETE localhost:8080/api/templates/my-custom-check
# read safe upstream-sync configuration (viewer)
curl -sb jar.txt localhost:8080/api/templates/sync
# queue an upstream refresh now (operator)
curl -sb jar.txt -X POST localhost:8080/api/templates/sync
# recent upstream-sync outcomes (for the Sync view)
curl -sb jar.txt localhost:8080/api/templates/sync-runs
```

The list response is a `{items, total, limit, offset}` page; list rows omit the `yaml` body
(fetch a single template to get it). Filters: `source`, repeatable/CSV `severity` and `tag`
(any-of), free-text `q` (matches id/name/description), and `include_unavailable=true` to include
tombstoned upstream rows (removed upstream but retained so curated sets don't silently lose
members). Sorting accepts `sort=name|severity|source|inserted|revision` plus
`order=asc|desc`; severity uses Nuclei's semantic critical-to-info order. CVE templates use the
canonical `cve` tag, so no separate CVE-only filter is needed. `sort=inserted&order=desc` orders
by NSC's `created_at` ingestion timestamp, newest first; this is labelled
**Inserted** because the upstream catalog does not provide an authoritative ProjectDiscovery
added/updated timestamp. `GET /api/templates/ids` accepts the same filters and returns all matching
ids without pagination.

Only **custom** templates are writable — `POST` takes YAML and parses it server-side (the YAML is
stored byte-for-byte; the typed fields are extracted for filtering), create/edit is `operator`,
delete is `admin`. Mutating an **upstream** row is refused (`409`, it's owned by the syncer), and a
custom `id` that collides with an existing template (custom or upstream) is a `409` — that's how a
custom template is prevented from shadowing an upstream one. Reads are `viewer`; writes are audited
as `config_changed` (`template.create` / `template.update` / `template.delete`). A successful
create/update response also includes
`validation: {valid:true, errors:[], nuclei_version:"v…"}`, identifying the deployed engine that
accepted it.

`GET /api/templates/sync` returns whether upstream mirroring is enabled plus its interval,
repository, ref, active catalog bundle digest (`templates_commit`), and active template count. The
digest is the same identifier shown for each scanner node, so an administrator can see whether a
node matches the backend catalog. The cache path is not exposed, and credentials/query strings are
stripped from repository URLs. `POST /api/templates/sync` queues a refresh and returns `202`;
requests coalesce behind a running or already-queued refresh. It returns `503` when
`TEMPLATE_SYNC_REPO` is empty. The request is `operator`-only and audited as `config_changed`
(`templates.sync_requested`); the eventual background outcome remains visible in
`/api/templates/sync-runs`. Each completed run includes the resulting `templates_commit` and
`template_count`; failed runs carry the unchanged active state. These historical bundle IDs let an
administrator identify which catalog snapshot a stale scanner node still holds.
Sync runs are retained in PostgreSQL rather than deleted. `GET /api/templates/sync-runs` returns
the standard `{items,total,limit,offset}` page, ordered newest first, so the UI can page through the
full history instead of silently capping it.

Custom uploads are sanity-checked at write time (all `400` on failure): the body must be a single
YAML document with a top-level `id`, a non-empty `info.name`, a severity in Nuclei's set
(`info`/`low`/`medium`/`high`/`critical`/`unknown`), and at least one executable section (a protocol
block — `http`, `dns`, `network`, `ssl`, … — or `workflows`). The `id` must be a URL-safe slug (no
slashes), and on edit the `id` inside the body must equal the `{id}` in the URL. These checks are the
cheap first line of defense; the upstream sync is intentionally *not* held to them (the community
tree is authoritative). After those checks, create/update sends the exact YAML to the first
registered node (ordered by name) that the health monitor has positively observed as healthy. That
node runs its pinned `nuclei -validate` without a target. A Nuclei rejection is `400` with bounded
diagnostics and nothing is persisted. If no validator is known healthy, every healthy candidate
fails in transit, validation times out, or the node cannot execute Nuclei, the write fails closed
with `503` plus `Retry-After: 5`. Archive imports use the same fail-closed boundary through one
bounded batch process, described under [Template portability](#template-portability).

### Template portability

Viewer-role users can export selected templates or one template set; operators can import
those files into another NSC instance:

```sh
# export selected templates as a lossless YAML tarball
curl -sb jar.txt -o templates.tar.gz \
  'localhost:8080/api/templates/export?ids=custom-one,custom-two&format=yaml'
# or as one JSON portability document (the raw YAML is retained as a string)
curl -sb jar.txt -o templates.json \
  'localhost:8080/api/templates/export?ids=custom-one&format=json'
# an exact set export also contains its name and exact member ids
curl -sb jar.txt -o portable-set.tar.gz \
  'localhost:8080/api/template-sets/<set_id>/export?format=yaml'

# import templates, or atomically restore a set plus its custom members
curl -sb jar.txt -X POST -F file=@templates.tar.gz \
  'localhost:8080/api/templates/import?on_conflict=skip'
curl -sb jar.txt -X POST -F file=@portable-set.tar.gz \
  'localhost:8080/api/template-sets/import?on_conflict=rename'
```

`format=yaml` is a gzip-compressed tar with `manifest.json`, the verbatim files under
`templates/<source>/<path>`, and (for set exports) `set.json`. `format=json` is one JSON document
carrying the same manifest fields and each template's verbatim YAML string; a set export includes a
`set` object. Both forms carry SHA-256 digests and round-trip custom YAML byte-for-byte. A set
export records its explicit `mode`; `exclude` exports `excluded_template_ids` and includes YAML
for referenced custom exclusions so the exclusion list can travel with the set, while catalog-
derived membership is never frozen.

The optional `on_conflict` strategy defaults to `skip`:

- `skip` leaves existing custom templates and an existing same-name set unchanged.
- `overwrite` replaces existing **custom** YAML and membership; it never overwrites sync-owned
  upstream rows.
- `rename` creates deterministic `-imported[-N]` template ids (rewriting the YAML `id`) and an
  `(imported [N])` set name, then maps membership to the renamed ids.

Upstream entries are verified but ignored on write because the syncer owns them. A set import
therefore requires each referenced upstream id to exist in the destination catalog; this preserves
the exact member-id contract instead of silently producing a partial set. Import is one database
transaction and returns template counts plus the resulting set/status. The upload boundary accepts
one multipart `file`, caps the request at 64 MiB, caps expanded tar content at 256 MiB / 25,000
files, rejects traversal, links, duplicate/unreferenced files, unknown JSON fields, digest mismatch,
invalid YAML, and incomplete sets. Imports are audited as `config_changed` with action
`templates.import`.

Exclude-mode imports apply the same fail-closed rule to `excluded_template_ids`: every excluded id
must exist in the destination catalog (or be supplied as a custom template in the archive), so an
export from a newer catalog can return `400` on an older destination rather than silently losing a
deny-list entry. Archives from the pre-mode shape are accepted and normalized (`dynamic_all=false`
to `exact`, `dynamic_all=true` without exclusions to `all`, otherwise to `exclude`).

After conflict resolution, every custom template selected for create, overwrite, or rename is packed
into one transient verified bundle and sent to a known-healthy scanner node. The node runs a single
pinned `nuclei -validate` process over the batch; skipped items and upstream reference material are
not revalidated. A mixed valid/invalid batch returns `400` with bounded per-template diagnostics and
persists nothing. No healthy validator, timeout, or node transport/execution failure returns `503`
with `Retry-After: 5`, also before persistence. A successful response includes
`validation: {valid:true, failures:[], errors:[], nuclei_version:"v…"}` when custom writes were
validated; it omits `validation` when the conflict policy selected no custom writes.

## Config: scan policies

A **scan policy** is the central, reusable **how to scan** configuration. It bundles a required
**template set** (`template_set_id`, exact/all/exclude) and Nuclei's execution knobs
(`rate_limit` / `concurrency` / `timeout_sec` / `max_host_error`). Every scan and schedule
selects both a policy and an approved target, allowing one policy to be reused across scopes.
Each knob is optional: a `null` (omitted) field means "use the built-in default" (rate `150` /
concurrency `25` / timeout `600`s / `max_host_error` Nuclei's own `30`), so a policy can tune
just one knob and leave the rest alone.

Because the policy is reusable, its discovery mode, rate, timeouts, and host-error tolerance are
applied unchanged to whichever target is selected. Operators should confirm those settings suit
the chosen scope, especially before pointing a high-rate policy at a fragile device.

The optional naabu host-discovery setting is independent from `discovery_scan_type`. Leave
`discovery_host_discovery` unset (or `null`) to preserve the mode default — host discovery for SYN and
no host discovery for connect. Set it to `true` to run the host-discovery pass before either port-scan
mode, or `false` to scan every target host directly with either mode. Host discovery still fails closed
on any naabu error. The host-discovery pass uses SYN/raw-socket probes even when the port-scan mode is
`connect`, so that combination requires the node capabilities normally needed for SYN; it is still
useful on a privileged node when connect is preferred for the port scan.

`max_host_error` is Nuclei's `-max-host-error`: how many errors a single host may accumulate
(across every protocol, not per port) before Nuclei abandons it for the rest of the run —
silently skipping executors that hadn't run yet (e.g. the SSL/TLS pass). Raising it, and/or
lowering the rate, is the fix for scanning fragile devices that trip the default of 30 on HTTP
alone.

```sh
# a policy for fragile devices: select templates, slow down, tolerate more host errors
curl -sb jar.txt -X POST localhost:8080/api/scan-policies -H 'content-type: application/json' -d '{
  "name": "fragile-device",
  "template_set_id": "<template_set_id>",
  "rate_limit": 20,
  "concurrency": 5,
  "max_host_error": 100,
  "discovery_scan_type": "syn",
  "discovery_host_discovery": false
}'
# launch it against an approved target
curl -sb jar.txt -X POST localhost:8080/api/scans \
  -d '{"scan_policy_id":"<policy_id>","target_id":"<target_id>"}'
```

Full REST set: `GET|POST /api/scan-policies`, `GET|PUT|DELETE /api/scan-policies/{id}` (reads
`viewer`, create/edit `operator`, delete `admin`, audited as `config_changed`). The
`template_set_id` must reference an existing row (`400` otherwise). Deleting a policy nulls the
link on past scans (history survives) and **cascades away any schedules built on it**. Deleting a
target cascades schedules for that target but leaves policies intact. A template set referenced
by a policy cannot be deleted until the policy is changed or removed.

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
  See [Administration → Backend-to-scanner TLS and mTLS](ADMIN_GUIDE.md#backend-to-scanner-tls-and-mtls).
- Endpoints: `GET|POST /api/nodes`, `GET|PUT|DELETE /api/nodes/{id}`.
- **Health (#98):** the backend polls each node's `GET /v1/capabilities`
  (`nuclei_version`, `templates_commit`) every
  `NODE_HEALTH_INTERVAL` to derive liveness; `healthy` is `null` until the first poll. When a node
  is unhealthy, `health_error` carries the last poll failure (e.g. `capabilities: 401 Unauthorized`
  for a wrong token vs. a connection error for an unreachable node), so the cause is visible without
  reading server logs. A scan whose matching node is known-unhealthy fails fast with a clear error.
  Config (`SCANNER_URL`/`SCAN_ZONES`) seeds this registry on first boot only —
  see [Administration → Scanner fleet](ADMIN_GUIDE.md#scanner-fleet).

A node's read view also carries `templates_synced_at` — when the backend last pushed the full
template catalog to it (#85). The backend does this automatically on a cadence
(`TEMPLATE_DISTRIBUTE_INTERVAL`, stale + idle nodes only), before a scan when selected templates
are newer or the reported digest differs, and on admin request:

```sh
# push the current full catalog to one node now (admin) → { templates_commit, template_count }
curl -sb jar.txt -X POST localhost:8080/api/nodes/<node_id>/templates/sync
```

`404` for an unknown node; `502` if the node rejects the bundle or is unreachable. A node returns
`409` when a scan is holding the active tree; automatic pre-dispatch top-up waits and retries,
while a later cadence retries a skipped periodic push. Audited `config_changed`
(`scanner_node.templates_sync`).

## Scope guardrail

A scan may only target hosts that fall inside an **approved target record**. This is the most
important guardrail: for an active scanner, accidentally aiming at out-of-scope or third-party
assets is the difference between a tool and an incident. Every scan selects a **scan policy**
and a stored **target**, so it is **in scope by construction**: there is no path to name a host
that isn't already an approved target. (Targets remain a first-class resource so `host_count`
and the allowlist stay meaningful, and policies can be reused across approved scopes.)

Target hosts themselves are still validated as hostnames/IPs/CIDRs/URLs when a target is
created. The allowlist **fails closed** — with no approved targets, no scan can run.

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
Successful `scan.create`, manual `schedule.run`, and cron dispatch actions also carry the resolved
`scan_policy_id`, `target_id`, and `scan_id`, so the selected scope remains attributable outside
the application database. Cron dispatches identify their actor as `system`.
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
configuration is in [Administration → Object storage](ADMIN_GUIDE.md#object-storage).
