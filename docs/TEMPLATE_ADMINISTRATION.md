# Template administration

This is the short operator guide for the template catalog introduced in #85. It is written so a
product owner can verify the design through the web UI without using the API.

## The model in one minute

1. **Postgres owns the catalog.** Templates have a unique Nuclei `id` and are either:
   - **upstream** — mirrored from the configured Nuclei templates repository; or
   - **custom** — organization-authored YAML stored byte-for-byte.
2. **Template sets are exact selections.** Filters help find templates in the editor, but a saved
   set records explicit IDs. A later upstream sync does not silently add newly matching templates.
3. **Scan policies choose the templates.** A policy references one target and optionally one
   template set. No set means all active templates.
4. **Scanner nodes receive the full active catalog.** Before a scan, the backend ensures the chosen
   node has the current content-addressed bundle. The node selects the policy's exact IDs from that
   verified bundle.
5. **Scans are reproducible.** Each scan records the concrete template IDs and full-catalog digest
   (`templates_commit`) used by the scanner.

This preserves the main security boundary: the backend owns configuration and persistence; scanner
nodes hold no database credentials and never pull templates or call back.

## Roles

| Action | Minimum role |
|---|---|
| Browse templates, view sets, export templates/sets | Viewer |
| Sync upstream, create/edit custom templates, curate sets, import, create scan policies | Operator |
| Delete custom templates/sets, manage nodes, manually push a node bundle | Admin |

All mutations are written to the structured audit log.

## PO acceptance test

### 1. Start with a healthy node

For the local stack:

```sh
cp .env.example .env
docker compose up --build
```

Open <http://localhost:8080> and sign in as `admin` / `admin`.

Go to **Scanner Nodes**. Confirm the default node becomes **Healthy** and shows:

- a Nuclei version;
- a recent **Last seen** value; and
- either an active template digest or **none active** before the first push.

Node health is initially unknown until the first capability poll. Custom-template writes fail
closed with `503` during that brief window or whenever no validator is healthy.

### 2. Mirror and browse upstream templates

Go to **Templates → Sync**.

1. Confirm sync is enabled and the configured repository/ref look correct.
2. Select **Sync now**.
3. Watch **Recent sync runs** for completion and the created/updated/tombstoned counts.
4. Return to **Catalog** and search by text, source, severity, or tags.
5. Open a row and confirm its YAML is viewable but an upstream template cannot be edited.

The first community-repository clone can be large and take several minutes. Subsequent runs reuse
the configured cache. If `TEMPLATE_SYNC_REPO` is empty, upstream sync is disabled but custom-only
catalogs still work.

An upstream template removed by a later sync is retained as **unavailable**, not silently deleted.
This keeps historical and set references explainable.

### 3. Prove authoritative custom validation

Go to **Templates → Custom templates → New custom template** and save:

```yaml
id: po-template-smoke
info:
  name: PO template smoke test
  author: product
  severity: info
  tags: po,smoke
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
```

Expected result:

- the template is saved losslessly;
- the success notice identifies the deployed Nuclei version that accepted it; and
- the template appears in both **Custom templates** and **Catalog**.

Now create another template with a different `id`, but change `200` to `not-a-number`.

Expected result:

- the lightweight metadata checks pass, then the scanner's pinned `nuclei -validate` rejects the
  schema;
- the UI displays bounded Nuclei diagnostics; and
- the invalid template does not appear in the catalog.

Also verify these guardrails:

- an ID containing `/` is rejected;
- a duplicate upstream/custom ID returns a conflict;
- editing cannot change the ID inside the YAML; and
- stopping the scanner or breaking its token causes create/edit to fail closed, never persist
  unvalidated YAML.

Custom validation starts with the first node already observed as healthy, ordered deterministically
by node name, and may fail over to another healthy node after a transport failure. It does not run a
target or perform a scan.

### 4. Curate an explicit template set

Go to **Template Sets → New template set**.

1. Name it `po-smoke-set`.
2. Use the filters to locate `po-template-smoke` and one upstream template.
3. Check both rows and save.
4. Reopen the set and confirm it contains exactly two IDs.
5. Change a search filter without checking another row; confirm the saved membership does not
   change.
6. Use **Select all matching** with a filter and confirm it selects matches across every page.

An empty set may be saved for later curation, but cannot be selected by a scan policy.

Create a second set in **All active templates (dynamic)** mode. Its member count follows the active
catalog and later upstream additions are included automatically.

### 5. Push and inspect the node bundle

Go to **Scanner Nodes** and select **Sync templates** on the healthy node.

Expected result:

- the UI reports the template count and catalog digest;
- the node's **Catalog bundle** column shows the same digest as **Templates → Sync**, plus the push
  time; and
- the custom template is included because nodes receive the full active catalog, not only upstream
  content.

Normal operation does not require this button. The backend also pushes stale bundles:

- on `TEMPLATE_DISTRIBUTE_INTERVAL`;
- immediately before dispatch when the selected node is behind; and
- only while the node's active template tree is not held by a scan.

A busy node can return `409`; automatic distribution retries rather than swapping files underneath
an active Nuclei process.

### 6. Use the set in a scan

1. Create or select an approved **Target**.
2. Go to **Scan Policies → New scan policy**.
3. Choose the target and `po-smoke-set`.
4. Save the policy.
5. Go to **Scans**, launch that policy, and open the completed scan.

Expected result:

- empty exact sets cannot be selected and every policy requires a set;
- dispatch ensures the matching node has the current bundle;
- the scan records its Nuclei version and `templates_commit`; and
- the selected IDs, not a filter or Git checkout, determine what Nuclei runs.

Choose the explicit dynamic set when the policy should scan every active catalog template. Use that
mode carefully on large catalogs.

### 7. Test portability

From **Templates → Catalog**, select templates and export either:

- **YAML archive** for an inspectable lossless package; or
- **JSON** for a single structured portability document.

From **Template Sets**, export `po-smoke-set` to carry its name, exact membership, and required
custom YAML. Import it again with one conflict policy:

- **skip** — retain existing custom templates/set;
- **overwrite** — replace existing custom YAML/set membership; or
- **rename** — create deterministic `-imported[-N]` IDs and rewrite set membership.

Upstream content in an import is ignored because the configured sync source owns it. Import is
atomic: the set is never restored with missing custom members.

Expected validation behavior:

- conflict policy is resolved first; only final custom creates, overwrites, and renamed YAML are
  selected;
- those selected files are validated by one bounded Nuclei process, not one process per file;
- a mixed valid/invalid archive identifies the rejected template and persists nothing;
- a successful notice reports the deployed Nuclei version; and
- an all-skipped/upstream-only import needs no validator because it has no custom writes.

## Routine administration

- Review **Templates → Sync** for failed upstream runs and tombstone counts.
- Review **Scanner Nodes** for health, Nuclei-version drift, catalog-digest drift, and last push.
- Curate sets by explicit ID; do not assume a search filter is saved.
- Export important custom templates/sets before moving them between environments.
- After deleting a custom template, review affected sets: membership is removed automatically and a
  one-member set becomes empty and unusable by a policy.
- After upstream tombstones, update any set containing an unavailable ID; scans fail closed rather
  than silently omitting it.
- Upgrade Nuclei by rebuilding the scanner image with the pinned `NUCLEI_VERSION`, then confirm node
  capabilities before accepting new custom templates.

## Troubleshooting

| Symptom | Meaning / action |
|---|---|
| Custom save returns `400` with Nuclei diagnostics | Fix the YAML schema. Nothing was persisted. |
| Custom save returns `503` | No known-healthy validator completed the request. Check node health, endpoint, token/mTLS, and Nuclei availability; then retry. |
| Import returns `400` with a template ID | Fix that archive entry. The entire selected batch was rejected and nothing was persisted. |
| Import returns `503` | Selected custom writes required validation, but no healthy node completed it. Restore node health and retry. |
| Upstream sync is disabled | Configure `TEMPLATE_SYNC_REPO`, or intentionally operate a custom-only catalog. |
| Set cannot be selected in a policy | Add members to an empty exact set, choose a dynamic set, or replace unavailable members. |
| Manual node sync returns `409` | A scan is using the active bundle. Wait for it to finish and retry. |
| Manual node sync returns `502` | Check node reachability, authentication/mTLS, disk space, and bundle diagnostics. |
| Scan reports template ID/digest drift | Push the current catalog, verify node health/storage, and retry. The node correctly refused unreproducible execution. |

For exact endpoints and response fields, see [API.md](API.md#template-catalog). For deployment
settings, see [CONFIGURATION.md](CONFIGURATION.md).
