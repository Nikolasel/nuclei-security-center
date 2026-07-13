// Typed client for the backend JSON API (served same-origin under /api). The SPA
// always authenticates with the BFF session cookie — it never presents a token.
// (Service-account tokens are minted here as an admin action and shown to the
// operator once; they are payload to display, never a credential this app uses.)

export interface Identity {
  subject: string;
  email?: string;
  name?: string;
  roles: string[];
}

// host_count is the real address-range size of `hosts` (a CIDR entry counts as
// its full range, e.g. "10.0.0.0/24" is 256) — not hosts.length, which only
// counts array entries and undercounts any target scoped to a CIDR.
export interface Target {
  id: string;
  name: string;
  hosts: string[];
  host_count: number;
  tags: string[];
  created_by?: string;
  created_at: string;
  updated_at: string;
}

// ScannerNode is a registered scanner endpoint the backend dispatches to (#22).
// `cidrs` are the ranges it serves (empty = a catch-all for hostname/unmatched
// targets). `token` is write-only — it is set on create/edit but never returned,
// so it's absent here. Health fields (#98) are derived from the backend's poll of
// the node's /v1/capabilities: `healthy` is null until the first poll (unknown).
export interface ScannerNode {
  id: string;
  name: string;
  endpoint: string;
  cidrs: string[];
  tags: string[];
  /** optional per-node mTLS (#26). `tls_server_ca` pins the node's server cert and
   *  `tls_client_cert` is the cert the backend presents — both public, returned
   *  here. The client key is a write-only secret and is never returned. */
  tls_server_ca?: string;
  tls_client_cert?: string;
  healthy?: boolean | null;
  last_seen?: string;
  nuclei_version?: string;
  /** the last poll failure's message; present only while unhealthy (e.g. a 401
   *  from a wrong token, or a connection error from an unreachable node). */
  health_error?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

/** ScannerNodeInput is the create/edit payload. `token` and `tls_client_key` are
 *  write-only secrets — required-together-or-omitted on create; on edit, leave
 *  them blank to keep the stored values. The server CA / client cert are public. */
export interface ScannerNodeInput {
  name: string;
  endpoint: string;
  token?: string;
  cidrs: string[];
  tags: string[];
  tls_server_ca?: string;
  tls_client_cert?: string;
  tls_client_key?: string;
}

export interface TemplateSet {
  id: string;
  name: string;
  git_ref?: string;
  severities: string[];
  tags: string[];
  paths: string[];
  created_by?: string;
  created_at: string;
  updated_at: string;
}

// Schedule ties a target (+ optional template set) to a cron expression. The
// backend ticker dispatches schedules whose next_run_at has arrived. next_run_at
// is null when disabled; last_run_at/last_scan_id record the most recent run.
export interface Schedule {
  id: string;
  name: string;
  target_id: string;
  template_set_id?: string;
  cron: string;
  enabled: boolean;
  timeout_sec?: number;
  next_run_at?: string;
  last_run_at?: string;
  last_scan_id?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

// ServiceAccount is an NSC-local identity for headless automation (#70), scoped
// to one role and authenticated with a bearer token. Only the token's hash is
// stored server-side, so `token_prefix` (the cleartext leading characters) is all
// the UI can show of an existing token — enough to match a row to the string an
// operator saved. expires_at is absent when the token never expires.
export interface ServiceAccount {
  id: string;
  name: string;
  role: string;
  token_prefix: string;
  created_by?: string;
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
}

/** ServiceAccountWithToken is the create/rotate response. `token` is the only
 *  time the plaintext token exists outside the caller's hands — the server keeps
 *  just its hash, so it can never be retrieved again and the UI must surface it
 *  immediately. */
export interface ServiceAccountWithToken extends ServiceAccount {
  token: string;
}

export const ASSIGNABLE_ROLES = ["viewer", "operator", "admin"] as const;

/** Default token lifetime in days, mirroring the backend's defaultTokenTTLDays.
 *  0 means no expiry. */
export const DEFAULT_TOKEN_TTL_DAYS = 90;

export type ScanState = "queued" | "running" | "complete" | "failed" | "cancelled";

// ScanProgress is live progress for a running scan (#66), parsed from Nuclei's
// -stats-json on the scanner node. Present only while a scan is running.
export interface ScanProgress {
  percent: number;
  requests?: number;
  total?: number;
  hosts?: number;
  rps?: number;
  matched?: number;
}

export interface Scan {
  id: string;
  state: ScanState;
  /** the stored target the scan ran against; absent for an ad-hoc spec scan. */
  target_id?: string;
  target_name?: string;
  target_host_count?: number;
  nuclei_version?: string;
  templates_commit?: string;
  error?: string;
  /** whether the verbatim Nuclei output was archived to object storage. */
  has_raw?: boolean;
  /** live progress; present only for running scans. */
  progress?: ScanProgress;
  created_at: string;
  finished_at?: string;
}

/** scanRawUrl is the download URL for a scan's archived raw Nuclei output
 *  (out.jsonl). The browser navigates to it so the same-origin session cookie
 *  authenticates the download (like findingsExportUrl). */
export function scanRawUrl(id: string): string {
  return `/api/scans/${id}/raw`;
}

// Occurrence is one per-scan observation (the immutable scan-detail row). It
// links to its deduplicated lifecycle finding via finding_id.
export interface Occurrence {
  id: number;
  scan_id: string;
  finding_id?: number;
  template_id: string;
  name: string;
  severity: string;
  host: string;
  matched_at: string;
  type: string;
  cve: string[];
  tags: string[];
  created_at: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

// Disposition is the manual analyst overlay (Tenable-style). Closure is
// evidence-driven — there is no manual "fixed"; the scanner mitigates.
export type Disposition = "none" | "false_positive" | "accepted";
export const DISPOSITIONS: Disposition[] = ["none", "false_positive", "accepted"];
export const DISPOSITION_LABELS: Record<Disposition, string> = {
  none: "None",
  false_positive: "False positive",
  accepted: "Accept risk",
};

// DetectionState is derived from scan observation; EffectiveState overlays the
// disposition (accepted / false_positive win) on top of it.
export type DetectionState =
  | "new"
  | "active"
  | "resurfaced"
  | "mitigated"
  | "previously_mitigated";
export type EffectiveState = DetectionState | "accepted" | "false_positive";
export const EFFECTIVE_STATES: EffectiveState[] = [
  "new",
  "active",
  "resurfaced",
  "mitigated",
  "previously_mitigated",
  "accepted",
  "false_positive",
];
export const STATE_LABELS: Record<EffectiveState, string> = {
  new: "New",
  active: "Active",
  resurfaced: "Resurfaced",
  mitigated: "Mitigated",
  previously_mitigated: "Prev. mitigated",
  accepted: "Accepted",
  false_positive: "False positive",
};

// LifecycleFinding is the deduplicated, triageable entity keyed on
// (target, template, matched_at). detection_state / effective_state and
// effective_severity (recast-aware) are all derived server-side.
export interface LifecycleFinding {
  id: number;
  target_id?: string;
  template_id: string;
  name: string;
  severity: string;
  recast_severity?: string;
  effective_severity: string;
  host: string;
  matched_at: string;
  type: string;
  cve: string[];
  tags: string[];
  disposition: Disposition;
  accept_expires_at?: string;
  detection_state: DetectionState;
  effective_state: EffectiveState;
  times_mitigated: number;
  first_seen_scan?: string;
  last_seen_scan?: string;
  first_seen_at: string;
  last_seen_at: string;
  latest_occurrence_id?: number;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface FindingsQuery {
  targetId?: string;
  q?: string;
  severities?: string[];
  host?: string;
  cve?: string;
  tag?: string;
  disposition?: Disposition;
  state?: EffectiveState;
  limit?: number;
  offset?: number;
}

export type ExportFormat = "json" | "csv" | "sarif" | "raw";

/** findingsExportUrl builds the download URL for the lifecycle findings export,
 *  reusing the same filter params as the list. The browser navigates to it so the
 *  same-origin session cookie authenticates the request (it's a file download,
 *  not JSON, so it bypasses the fetch helper). */
export function findingsExportUrl(format: ExportFormat, q: FindingsQuery = {}): string {
  const p = new URLSearchParams();
  p.set("format", format);
  if (q.targetId) p.set("target_id", q.targetId);
  if (q.q) p.set("q", q.q);
  if (q.severities?.length) p.set("severity", q.severities.join(","));
  if (q.host) p.set("host", q.host);
  if (q.cve) p.set("cve", q.cve);
  if (q.tag) p.set("tag", q.tag);
  if (q.disposition) p.set("disposition", q.disposition);
  if (q.state) p.set("state", q.state);
  return `/api/findings/export?${p.toString()}`;
}

export interface ScanFindingsQuery {
  q?: string;
  severities?: string[];
  host?: string;
  cve?: string;
  tag?: string;
  limit?: number;
  offset?: number;
}

/** NucleiRaw models the subset of a Nuclei JSONL finding the detail view renders.
 *  Fields are optional — templates emit different shapes. */
export interface NucleiRaw {
  "template-id"?: string;
  "template-url"?: string;
  "matcher-name"?: string;
  type?: string;
  host?: string;
  ip?: string;
  port?: string;
  scheme?: string;
  url?: string;
  "matched-at"?: string;
  "extracted-results"?: string[];
  request?: string;
  response?: string;
  "curl-command"?: string;
  timestamp?: string;
  info?: {
    name?: string;
    author?: string[];
    tags?: string[];
    description?: string;
    reference?: string[];
    severity?: string;
    remediation?: string;
    classification?: {
      "cve-id"?: string[];
      "cwe-id"?: string[];
      "cvss-metrics"?: string;
      "cvss-score"?: number;
      "epss-score"?: number;
    };
  };
  [key: string]: unknown;
}

export interface FindingDetail extends LifecycleFinding {
  disposition_note?: string;
  disposition_by?: string;
  disposition_at?: string;
  recast_note?: string;
  recast_by?: string;
  recast_at?: string;
  raw?: NucleiRaw;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = (await res.text()).trim();
    throw new ApiError(res.status, text || res.statusText);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") ?? "";
  if (!ct.includes("application/json")) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  me: () => request<Identity>("GET", "/api/auth/me"),

  listTargets: () => request<Target[]>("GET", "/api/targets"),
  createTarget: (t: Partial<Target>) => request<Target>("POST", "/api/targets", t),
  updateTarget: (id: string, t: Partial<Target>) =>
    request<Target>("PUT", `/api/targets/${id}`, t),
  deleteTarget: (id: string) => request<void>("DELETE", `/api/targets/${id}`),

  // Scanner nodes (#22). Reads are viewer; create/update/delete are admin. The
  // token is write-only — never returned, blank on update keeps the stored one.
  listNodes: () => request<ScannerNode[]>("GET", "/api/nodes"),
  createNode: (n: ScannerNodeInput) => request<ScannerNode>("POST", "/api/nodes", n),
  updateNode: (id: string, n: ScannerNodeInput) =>
    request<ScannerNode>("PUT", `/api/nodes/${id}`, n),
  deleteNode: (id: string) => request<void>("DELETE", `/api/nodes/${id}`),

  listTemplateSets: () => request<TemplateSet[]>("GET", "/api/template-sets"),
  createTemplateSet: (t: Partial<TemplateSet>) =>
    request<TemplateSet>("POST", "/api/template-sets", t),
  updateTemplateSet: (id: string, t: Partial<TemplateSet>) =>
    request<TemplateSet>("PUT", `/api/template-sets/${id}`, t),
  deleteTemplateSet: (id: string) => request<void>("DELETE", `/api/template-sets/${id}`),

  listSchedules: () => request<Schedule[]>("GET", "/api/schedules"),
  createSchedule: (s: Partial<Schedule>) => request<Schedule>("POST", "/api/schedules", s),
  updateSchedule: (id: string, s: Partial<Schedule>) =>
    request<Schedule>("PUT", `/api/schedules/${id}`, s),
  deleteSchedule: (id: string) => request<void>("DELETE", `/api/schedules/${id}`),
  runSchedule: (id: string) =>
    request<{ scan_id: string }>("POST", `/api/schedules/${id}/run`),

  // Service accounts (admin only). create/rotate return the plaintext token once.
  listServiceAccounts: () => request<ServiceAccount[]>("GET", "/api/service-accounts"),
  createServiceAccount: (body: { name: string; role: string; ttl_days?: number }) =>
    request<ServiceAccountWithToken>("POST", "/api/service-accounts", body),
  rotateServiceAccount: (id: string, body: { ttl_days?: number } = {}) =>
    request<ServiceAccountWithToken>("POST", `/api/service-accounts/${id}/rotate`, body),
  deleteServiceAccount: (id: string) => request<void>("DELETE", `/api/service-accounts/${id}`),

  listScans: () => request<Scan[]>("GET", "/api/scans"),
  getScan: (id: string) => request<Scan>("GET", `/api/scans/${id}`),
  createScan: (body: { target_id?: string; template_set_id?: string; timeout_sec?: number }) =>
    request<{ scan_id: string }>("POST", "/api/scans", body),
  cancelScan: (id: string) => request<void>("POST", `/api/scans/${id}/cancel`),
  deleteScan: (id: string) => request<void>("DELETE", `/api/scans/${id}`),

  listFindings: (q: FindingsQuery = {}) => {
    const p = new URLSearchParams();
    if (q.targetId) p.set("target_id", q.targetId);
    if (q.q) p.set("q", q.q);
    if (q.severities?.length) p.set("severity", q.severities.join(","));
    if (q.host) p.set("host", q.host);
    if (q.cve) p.set("cve", q.cve);
    if (q.tag) p.set("tag", q.tag);
    if (q.disposition) p.set("disposition", q.disposition);
    if (q.state) p.set("state", q.state);
    if (q.limit != null) p.set("limit", String(q.limit));
    if (q.offset != null) p.set("offset", String(q.offset));
    const qs = p.toString();
    return request<Page<LifecycleFinding>>("GET", qs ? `/api/findings?${qs}` : "/api/findings");
  },
  getFinding: (id: number | string) => request<FindingDetail>("GET", `/api/findings/${id}`),
  // Analyst overlays (operator only). accept_expires_at applies to "accepted".
  setDisposition: (
    id: number | string,
    body: { disposition: Disposition; note?: string; accept_expires_at?: string | null },
  ) => request<FindingDetail>("PATCH", `/api/findings/${id}/disposition`, body),
  // Recast Risk: override severity; pass severity "" to clear the recast.
  recastSeverity: (id: number | string, body: { severity: string; note?: string }) =>
    request<FindingDetail>("PATCH", `/api/findings/${id}/severity`, body),

  listScanFindings: (scanId: string, q: ScanFindingsQuery = {}) => {
    const p = new URLSearchParams();
    if (q.q) p.set("q", q.q);
    if (q.severities?.length) p.set("severity", q.severities.join(","));
    if (q.host) p.set("host", q.host);
    if (q.cve) p.set("cve", q.cve);
    if (q.tag) p.set("tag", q.tag);
    if (q.limit != null) p.set("limit", String(q.limit));
    if (q.offset != null) p.set("offset", String(q.offset));
    const qs = p.toString();
    return request<Page<Occurrence>>("GET", qs ? `/api/scans/${scanId}/findings?${qs}` : `/api/scans/${scanId}/findings`);
  },
};
