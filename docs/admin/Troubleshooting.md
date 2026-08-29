# Troubleshooting

| Symptom | Meaning / action |
|---|---|
| Backend reports unsupported migration versions or a missing checksum | The database history is not supported by the current fresh-deployment baseline. Preserve exports/backups as needed, deploy a new empty database, and restore portable data. |
| Backend cannot reach Postgres | Verify `DATABASE_URL`, TLS/network policy, credentials, and the password-file contents/permissions. |
| Login loops or callback fails | Match `APP_BASE_URL`, `OIDC_ISSUER`, and registered `OIDC_REDIRECT_URL`; use `OIDC_DISCOVERY_URL` only for internal metadata routing. |
| Login returns `503` temporarily | A short auth-flow admission collision survived the bounded retries. Retry the login navigation; sustained failures indicate database contention or availability trouble. |
| Login limiter treats all users behind the LB as one peer | Set `AUTH_TRUSTED_PROXY_CIDRS` to the LB/proxy source networks only, and verify the proxy strips or overwrites incoming `X-Forwarded-For`; otherwise use the LB/WAF per-client limiter. |
| Session works locally but not through ingress | Keep HTTPS end-to-end or at the ingress and verify `COOKIE_SECURE=true`, forwarded host/scheme, and the public base URL. |
| Node remains unknown/unhealthy | Check backend→node DNS/routing, endpoint scheme, bearer token, TLS CA/client pair, and `/v1/capabilities`. |
| Custom template returns `400` | Fix the Nuclei YAML using the returned diagnostics; nothing was persisted. |
| Custom template/import returns `503` | No known-healthy validator completed the request. Restore node health/token/TLS/Nuclei availability and retry. |
| Upstream sync is disabled | Set `TEMPLATE_SYNC_REPO`, or intentionally run a custom-only catalog. |
| First template sync is slow | The first clone is large. Persist `TEMPLATE_SYNC_DIR`; later runs fetch deltas. |
| Manual node sync returns `409` | A scan is using the active tree. Wait for it to finish. |
| Template ID/digest drift blocks dispatch | Sync the current catalog to the selected node and verify its persistent work storage. The refusal preserves reproducibility. |
| Custom deletion returns `409` | Remove the template from exclude-set exclusions first. |
| Policy cannot use a set | Populate an empty exact set, replace unavailable IDs, or ensure an exclude set does not exclude the entire active catalog. |
| Discovery fails with permission/libpcap errors | Use the scanner image with required libraries/capability, or set the policy/node to connect mode. |
| Docker Desktop reports every private-CIDR host alive | macOS VM/NAT can distort SYN host-discovery tally. Trust persisted discovered endpoints, use connect mode for local development, or verify SYN behavior on Linux/routable networks. |
| Archive endpoint returns `404` | `S3_ENDPOINT` is unset, the scan has no archive, or the object is unavailable. |
| Findings export returns `500 prepare findings export` | Verify `EXPORT_SPOOL_DIR` exists, is writable by the backend runtime user, and has at least 512 MiB of free space. |
| Object upload logs warnings but scan completes | Archival is best-effort by design; repair endpoint/credentials/bucket policy and test a new scan. |
| A finding does not auto-mitigate | Confirm a later complete scan ran the same template and request-trace evidence reached the same normalized host:port without skipped ingest. Missing coverage fails closed. |

For HTTP status codes and request/response shapes, continue with the [API reference](../API.md).
