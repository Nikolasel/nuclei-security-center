# First-run bootstrap

1. **Sign in as admin.** Confirm `/api/auth/me` shows the expected role mapping.
2. **Check Scanner Nodes.** The seeded default node starts as unknown, then should become healthy
   after the first capability poll and report its Nuclei version.
3. **Sync templates.** Open **Templates → Sync** and run the first upstream refresh. The initial
   community-repository clone is large; later runs reuse `TEMPLATE_SYNC_DIR`.
4. **Verify the catalog.** Confirm the sync run succeeded and the Catalog tab contains active
   templates. Removed upstream templates are retained as unavailable for explainability.
5. **Push the node bundle.** Automatic distribution handles this, but **Sync templates** on the node
   is a useful first-run verification. The node and catalog digests should match.
6. **Create the operating chain:** target → template set → scan policy → manual scan. Add a schedule
   only after the manual scan completes successfully.
7. **Verify archives and audit logs.** Download raw output/execution logs when object storage is
   enabled and confirm mutating actions appear as structured `event=audit` records in stdout.

Custom template writes intentionally fail with `503` until at least one validator node is known
healthy.
