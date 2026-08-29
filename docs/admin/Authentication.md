# Authentication

NSC is a confidential OIDC client. Tokens stay in the backend; browser JavaScript receives only an
httpOnly, SameSite session cookie. Map the configured claim to `admin`, `operator`, and `viewer`.
Reads require viewer, scan/config mutations generally require operator, and destructive/fleet
administration requires admin.

Environment variables for the IdP, cookie, session TTL, and login limiter are listed in
[Configuration → Authentication and sessions](Configuration.md#authentication-and-sessions).

## OIDC/BFF

Register the exact `OIDC_REDIRECT_URL` with the provider. If browser-facing and cluster-internal
issuer addresses differ, keep the canonical browser issuer in `OIDC_ISSUER` and use
`OIDC_DISCOVERY_URL` for backend metadata requests.

## Browser mutation protection

Cookie-authenticated state-changing API requests must carry an `Origin` matching the origin of
`APP_BASE_URL`. When a browser omits `Origin`, the backend accepts
`Sec-Fetch-Site: same-origin`; `same-site` is rejected because a sibling subdomain can be
attacker-controlled. The guard is applied centrally to mutations, including logout, and fails
closed when the configured public origin is missing or malformed. JSON-body endpoints also
require `Content-Type: application/json`, preventing simple HTML form bodies from reaching JSON
decoders. Service-account bearer-token callers are explicit rather than ambient credentials and
do not need browser-origin headers.

`POST /api/auth/logout` on success clears the local session; when the provider's discovery document
advertises an `end_session_endpoint` (optional per OIDC, scheme restricted to `http(s)` and host
required) the backend returns `200 JSON {end_session_url}` with `client_id` and an absolute
`post_logout_redirect_uri` (derived from `APP_BASE_URL`/`POST_LOGIN_REDIRECT` and whitelisted at
the IdP), which the SPA follows with a top-level navigation to terminate the IdP SSO cookie
(CWE-613 — shared-workstation reuse). Otherwise it returns `204` local-only logout. `GET
/api/auth/logout` is the direct-navigation companion: it accepts the same `same-origin` signal
plus `Sec-Fetch-Site: none` (address-bar/bookmark, no `Origin`) so a user who navigates to the
URL directly still clears both sessions on success, while site-controlled `cross-site`/`same-site`
navigations remain blocked. If server-side session revocation fails (transient Postgres outage) both
endpoints return `503 logout temporarily unavailable` with `Retry-After: 1`, preserve the browser
cookie so logout can be retried, and do not return/redirect to an `end_session_url` — no success
is presented until the session row is gone (#268). See the [API reference](../API.md) for the exact
status codes.

## Headless automation

Admins can create role-scoped, revocable NSC service-account tokens. Automation sends:

```http
Authorization: Bearer <token>
```

Use the least-privileged role, set an expiry where practical, rotate the token through the service
account API/UI, and revoke it independently of human IdP access. See
[API → Service accounts](../API.md#service-accounts).

## Backend-to-scanner TLS and mTLS

Bearer authentication always applies. For an untrusted segment:

1. Configure `SCANNER_TLS_CERT` and `SCANNER_TLS_KEY` on the node.
2. Set `SCANNER_CLIENT_CA` to require a backend client certificate.
3. In **Scanner Nodes**, configure that node's endpoint as `https://…`, pin its server CA, and store
   the backend client certificate/key.

The per-node client key and bearer token are write-only in API responses. Certificate issuance and
rotation remain deployment concerns; a service mesh may terminate mTLS instead.

## Session revocation and privilege-revocation latency

NSC is a BFF: role membership is snapshotted from the IdP's groups claim at login and stored in
the `sessions` row for the life of that session. The backend discards the OAuth tokens after the
callback, so there is no background IdP re-check. The worst-case window in which a demoted or
offboarded user retains their previous NSC role is therefore bounded by `SESSION_TTL` — at most
`24h` by configuration, `12h` by default.

An administrator can cut that window short at any time (copy the `subject` value
from the list output — it is the OIDC `sub` claim, an opaque stable identifier
often a UUID, *not* the email; using an email will match zero rows on most IdPs
and return 404):

- `GET /api/sessions?limit=&cursor=&q=` (admin) lists live sessions with their subject (`sub`), email, roles, and expiry. The endpoint is keyset-paginated (`limit` 1–200, default 50, `cursor` opaque, `next_cursor` in response) and supports a server-side filter `q` (matches subject/email/name/roles globally). Responses are `{items, total, limit, next_cursor}` — iterate via `next_cursor` until empty, reading `.items` (not a bare array). The per-subject cap is 20 live sessions (oldest evicted first); `limit` beyond 200 falls back to 50 and `q` is capped at 256 bytes. A temporary offset shim (`?limit=&offset=`) remains for a cached SPA but is deprecated.
- `DELETE /api/sessions/{id}` (admin) revokes a single session by its stored id.
- `DELETE /api/sessions?subject=<subject>` (admin) revokes **every** live session for one subject
  — the offboarding path. Returns 404 `no active sessions for subject` when the
  supplied `sub` matches no live session so a typo or email-instead-of-`sub`
  does not silently no-op. Offboarding automation should treat this 404 as
  already-clean (desired end state: zero sessions) rather than a failure. When scripting offboarding, iterate pages via `next_cursor` (do not assume one call returns the full set).

Both deletes are audited as `event_id=session_revoked` with `actor_type=user` (or
`service_account` when a token calls them); a 404 bulk response also emits
`session_revoked` with `revoked_count=0` and `status=404` so SIEM detections
should key on `revoked_count`/`status`, not just `event_id`. A revoked
session's cookie immediately yields `401` on the next request. Treat IdP group
removal or account disable as a trigger to call one of these endpoints so
revocation propagates within minutes rather than hours.

In the SPA this is exposed as **Admin → Sessions** (visible only to the `admin` role):
a live, server-side-filtered table grouped by subject — each group header shows the opaque
`sub` (mono line, the value to use for `?subject=`) alongside email/name and a
per-subject **Revoke all** (offboarding) button, plus a per-session **Revoke**
for targeted termination. The filter (`q`) is global across all pages (not just the
current page) and pagination uses a cursor over `(created_at DESC, id DESC)` so revocations
between pages do not cause skipped rows; navigation (Previous/Next) is rendered independently
of filtered results and an emptied page offers a clamp back to Previous/First page. The page polls `GET /api/sessions` and calls the same
`DELETE` endpoints above, so its audit trail is identical to the `curl` path.
