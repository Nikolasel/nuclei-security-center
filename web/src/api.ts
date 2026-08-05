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
  templates_commit?: string;
  templates_synced_at?: string;
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

export type TemplateSetMode = "exact" | "all" | "exclude";

export interface TemplateSet {
  id: string;
  name: string;
  mode: TemplateSetMode;
  member_count: number;
  exclusion_count: number;
  excluded_template_ids?: string[];
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export type TemplateSource = "upstream" | "custom";

export interface Template {
  id: string;
  source: TemplateSource;
  path: string;
  content_sha256: string;
  name: string;
  author: string;
  severity: string;
  description: string;
  tags: string[];
  upstream_ref?: string;
  revision: number;
  availability: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface TemplateDetail extends Template {
  yaml: string;
  validation?: {
    valid: boolean;
    errors: string[];
    nuclei_version: string;
  };
}

export type TemplateArchiveFormat = "yaml" | "json";
export type TemplateImportConflict = "skip" | "overwrite" | "rename";

export interface TemplateImportResponse {
  templates: {
    created: number;
    updated: number;
    skipped: number;
    upstream_ignored: number;
    renamed: { from: string; to: string }[];
  };
  validation?: {
    valid: boolean;
    failures: { template_id: string; errors: string[] }[];
    errors: string[];
    truncated?: boolean;
    nuclei_version: string;
  };
  set?: TemplateSet;
  set_status?: "created" | "updated" | "skipped" | "renamed";
}

export interface TemplatesQuery {
  source?: TemplateSource;
  severities?: string[];
  tags?: string[];
  q?: string;
  sort?: TemplateSort;
  order?: SortOrder;
  include_unavailable?: boolean;
  limit?: number;
  offset?: number;
}

export type TemplateSort = "name" | "severity" | "source" | "inserted" | "revision";
export type SortOrder = "asc" | "desc";

export interface TemplateSyncRun {
  id: string;
  started_at: string;
  finished_at?: string;
  status: string;
  ref_before?: string;
  ref_after?: string;
  templates_commit?: string;
  template_count?: number;
  added: number;
  removed: number;
  updated: number;
  skipped: number;
  error?: string;
}

export interface TemplateSyncStatus {
  enabled: boolean;
  interval?: string;
  repo?: string;
  ref?: string;
  templates_commit?: string;
  template_count: number;
}

// ScanPolicy (#87, reshaped by #137) is the reusable HOW-to-scan configuration:
// required templates plus Nuclei/discovery knobs. The approved target is chosen
// independently at ad-hoc launch or stored on a schedule. Each knob is optional:
// a null field means "use the built-in default"
// (rate 150 / concurrency 25 / timeout 600s / max-host-error Nuclei's own 30).
export interface ScanPolicy {
  id: string;
  name: string;
  template_set_id: string;
  rate_limit?: number | null;
  concurrency?: number | null;
  timeout_sec?: number | null;
  max_host_error?: number | null;
  // Discovery (#86): the optional naabu port-scan pre-pass. Runs before Nuclei so
  // it only probes live host:port pairs — the win for CIDR-scoped targets.
  // ON by default; it fails closed on the node, so disable it here when naabu is
  // unavailable. discovery_ports empty = naabu's top-1000 (nmap top-1000);
  // discovery_timeout_sec is discovery's own budget, separate from timeout_sec.
  discovery_enabled?: boolean | null;
  // Scan mode: "syn" (needs the node's CAP_NET_RAW + libpcap) or "connect"
  // (unprivileged). Empty = the node's
  // NAABU_SCAN_TYPE default; "syn" on a node without raw sockets fails closed.
  discovery_scan_type?: string;
  // Host discovery is independent from the port-scan mode (#133). Null/omitted
  // preserves today's default (on for SYN, off for connect); true/false forces it.
  discovery_host_discovery?: boolean | null;
  discovery_ports?: string;
  discovery_timeout_sec?: number | null;
  // naabu tuning (null = naabu's default): -rate (pkts/s), -timeout (ms/probe),
  // -retries. Lower values are faster but can miss slow/lossy ports.
  discovery_rate?: number | null;
  discovery_probe_timeout_ms?: number | null;
  discovery_retries?: number | null;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

// Schedule pairs an approved target with a reusable scan policy and cron cadence
// (#137). The backend ticker dispatches schedules whose
// next_run_at has arrived. next_run_at is null when disabled; last_run_at/
// last_scan_id record the most recent run.
export interface Schedule {
  id: string;
  name: string;
  scan_policy_id: string;
  target_id: string;
  cron: string;
  enabled: boolean;
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

// ScanProgress is live progress for a running scan, present only while running.
// `phase` says which stage it describes: "discovering" (naabu, #86) or "scanning"
// (Nuclei, #66). The Nuclei fields apply in the scanning phase; disc_hosts/
// disc_ports are the naabu live per-host tally in the discovering phase.
export interface ScanProgress {
  phase?: "discovering" | "scanning";
  percent: number;
  requests?: number;
  total?: number;
  hosts?: number;
  rps?: number;
  matched?: number;
  /** discovering phase: hosts found with ≥1 open port, and open ports so far. */
  disc_hosts?: number;
  disc_ports?: number;
}

export interface Scan {
  id: string;
  state: ScanState;
  /** the stored target the scan ran against; absent for an ad-hoc spec scan. */
  target_id?: string;
  target_name?: string;
  target_host_count?: number;
  /** the concrete template set resolved for this scan; absent after deletion. */
  template_set_id?: string;
  template_set_name?: string;
  /** the scan policy applied (#87); absent when the scan used the built-in
   *  defaults, or once the policy has been deleted. */
  scan_policy_id?: string;
  scan_policy_name?: string;
  /** the registered scanner node dispatch selected (#107); absent once the node
   *  is deleted or if the scan failed before a node was chosen. */
  node_id?: string;
  node_name?: string;
  nuclei_version?: string;
  templates_commit?: string;
  error?: string;
  /** source records skipped because they were malformed during backend ingest. */
  skipped_finding_count: number;
  /** whether the verbatim Nuclei output was archived to object storage. */
  has_raw?: boolean;
  /** whether the scanner's execution log (stdout/stderr) was archived (#94). */
  has_log?: boolean;
  /** live progress; present only for running scans. */
  progress?: ScanProgress;
  /** host:port endpoints the naabu pre-pass narrowed the target to (#86);
   *  persisted at completion, served live during the scanning phase. Empty when
   *  discovery was disabled. */
  discovered_targets?: string[];
  /** exact template+host:port pairs for which Nuclei recorded a successful
   *  request (#91). null/undefined means coverage telemetry is unavailable;
   *  [] is known zero. */
  covered_endpoints?: EndpointCoverage[] | null;
  /** fail-closed diagnostics when request-trace evidence was incomplete. */
  coverage_warning?: string;
  created_at: string;
  finished_at?: string;
}

export interface EndpointCoverage {
  template_id: string;
  endpoint: string;
}

/** scanRawUrl is the download URL for a scan's archived raw Nuclei output
 *  (out.jsonl). The browser navigates to it so the same-origin session cookie
 *  authenticates the download (like findingsExportUrl). */
export function scanRawUrl(id: string): string {
  return `/api/scans/${id}/raw`;
}

/** scanLogUrl is the download URL for a scan's archived execution log (Nuclei's
 *  stdout/stderr, #94), streamed through the BFF behind the session cookie. */
export function scanLogUrl(id: string): string {
  return `/api/scans/${id}/log`;
}

/** scanBundleExportUrl is the download URL for a complete scan bundle (JSON or
 *  zip, #136). The browser navigates to it so the same-origin session cookie
 *  authenticates the download, like scanRawUrl. */
export function scanBundleExportUrl(id: string, format: "json" | "zip" = "json"): string {
  return `/api/scans/${id}/export?format=${format}`;
}

/** ImportScanBundleResponse mirrors the backend's ScanImportResult (#136). */
export interface ImportScanBundleResponse {
  scan_id: string;
  findings_imported: number;
  lifecycle_created: number;
  lifecycle_updated: number;
  coverage_mode: "ignore" | "trust";
  fallbacks?: { field: string; exporter_id: string }[];
}

export type ImportCoverageMode = "ignore" | "trust";

/** importScanBundle uploads a scan bundle (a .nsc-bundle JSON or zip, #136) and
 *  recreates the scan and its results on this instance: the findings are
 *  re-derived via the normal ingest path, so this instance computes its own
 *  finding lifecycle from the imported results. The
 *  exporter's analyst overlays are never carried over. conflict=duplicate
 *  imports under a fresh id instead of failing with 409 when the exported scan
 *  id already exists here. Imported endpoint coverage is ignored by default;
 *  coverage="trust" is an explicit operator opt-in for mitigation evidence. */
export async function importScanBundle(
  file: File,
  conflict: "error" | "duplicate" = "error",
  coverage: ImportCoverageMode = "ignore",
): Promise<ImportScanBundleResponse> {
  const params = new URLSearchParams({ conflict, coverage });
  const res = await fetch(`/api/scans/import?${params.toString()}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/octet-stream" },
    body: await file.arrayBuffer(),
  });
  if (!res.ok) {
    const text = (await res.text()).trim();
    throw new ApiError(res.status, text || res.statusText);
  }
  return (await res.json()) as ImportScanBundleResponse;
}

// Occurrence is one per-scan observation (the immutable scan-detail row). It
// links to its deduplicated lifecycle finding via finding_id.
export interface Occurrence {
  id: number;
  scan_id: string;
  target_id?: string;
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

export interface OccurrenceDetail extends Occurrence {
  raw: NucleiRaw;
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

// LifecycleFinding is the globally deduplicated, triageable entity keyed on
// (template, matched_at, stable result variant). Scan/target are immutable
// occurrence provenance, not lifecycle identity.
export interface LifecycleFinding {
  id: number;
  target_ids: string[];
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
  /** false when matched_at has no network host:port, so absence cannot
   *  automatically become mitigation evidence. */
  auto_mitigation_eligible: boolean;
  first_seen_scan?: string;
  last_seen_scan?: string;
  first_seen_at: string;
  last_seen_at: string;
  latest_occurrence_id?: number;
}

// AppSettings is the global settings singleton (#95). Today it carries only the
// scan-retention policy. scan_retention_days is null when unset; retention only
// runs when retention_enabled is true AND the day window is a positive integer.
export interface AppSettings {
  retention_enabled: boolean;
  scan_retention_days: number | null;
  /** whether ad-hoc scans (not tied to a target) are also swept (#95). */
  retention_include_adhoc: boolean;
  updated_by?: string;
  updated_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

// The structured findings filter grammar (#97): OR-of-AND groups — groups are
// ORed, conditions within a group are ANDed. Compiles server-side to a
// parameterized WHERE. An empty `groups` matches everything.
export interface FindingCondition {
  field: string;
  op: string;
  values?: string[];
}
export interface FindingGroup {
  conditions: FindingCondition[];
}
export interface FindingQuery {
  groups: FindingGroup[];
}

// FindingsQuery carries the structured filter plus pagination.
export interface FindingsQuery {
  filter?: FindingQuery;
  limit?: number;
  offset?: number;
}

/** findingsParams serializes the filter into the query params shared by the list
 *  and export endpoints (so they stay in lockstep). The condition tree rides as
 *  one JSON `filter` param. */
function findingsParams(q: FindingsQuery): URLSearchParams {
  const p = new URLSearchParams();
  if (q.filter && q.filter.groups.length > 0) p.set("filter", JSON.stringify(q.filter));
  return p;
}

export type ExportFormat = "json" | "csv" | "sarif" | "raw";

/** findingsExportUrl builds the download URL for the lifecycle findings export,
 *  reusing the same filter params as the list. The browser navigates to it so the
 *  same-origin session cookie authenticates the request (it's a file download,
 *  not JSON, so it bypasses the fetch helper). */
export function findingsExportUrl(format: ExportFormat, q: FindingsQuery = {}): string {
  const p = findingsParams(q);
  p.set("format", format);
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
  "extractor-name"?: string;
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
  occurrence_count: number;
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

async function requestYAML<T>(method: string, path: string, yaml: string): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/yaml" },
    body: yaml,
  });
  if (!res.ok) {
    const text = (await res.text()).trim();
    throw new ApiError(res.status, text || res.statusText);
  }
  return (await res.json()) as T;
}

async function uploadArchive(
  path: string,
  file: File,
  conflict: TemplateImportConflict,
): Promise<TemplateImportResponse> {
  const form = new FormData();
  form.set("file", file);
  const res = await fetch(`${path}?on_conflict=${encodeURIComponent(conflict)}`, {
    method: "POST",
    credentials: "same-origin",
    body: form,
  });
  if (!res.ok) {
    const text = (await res.text()).trim();
    throw new ApiError(res.status, text || res.statusText);
  }
  return (await res.json()) as TemplateImportResponse;
}

async function downloadArchive(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) {
    const text = (await res.text()).trim();
    throw new ApiError(res.status, text || res.statusText);
  }
  const disposition = res.headers.get("content-disposition") ?? "";
  const match = disposition.match(/filename="([^"]+)"/i);
  const filename = (match?.[1] || fallbackName).split(/[\\/]/).pop() || fallbackName;
  const objectURL = URL.createObjectURL(await res.blob());
  const link = document.createElement("a");
  link.href = objectURL;
  link.download = filename;
  try {
    document.body.append(link);
    link.click();
  } finally {
    link.remove();
    setTimeout(() => URL.revokeObjectURL(objectURL), 0);
  }
}

function templateExportURL(ids: string[], format: TemplateArchiveFormat): string {
  const p = new URLSearchParams({ format });
  ids.forEach((id) => p.append("ids", id));
  return `/api/templates/export?${p.toString()}`;
}

function templateSetExportURL(id: string, format: TemplateArchiveFormat): string {
  return `/api/template-sets/${encodeURIComponent(id)}/export?format=${encodeURIComponent(format)}`;
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
  syncNodeTemplates: (id: string) =>
    request<{ templates_commit: string; template_count: number }>(
      "POST",
      `/api/nodes/${id}/templates/sync`,
    ),

  listTemplates: (q: TemplatesQuery = {}) => {
    const p = new URLSearchParams();
    if (q.source) p.set("source", q.source);
    if (q.severities?.length) p.set("severity", q.severities.join(","));
    if (q.tags?.length) p.set("tag", q.tags.join(","));
    if (q.q) p.set("q", q.q);
    if (q.sort) p.set("sort", q.sort);
    if (q.order) p.set("order", q.order);
    if (q.include_unavailable) p.set("include_unavailable", "true");
    if (q.limit != null) p.set("limit", String(q.limit));
    if (q.offset != null) p.set("offset", String(q.offset));
    const qs = p.toString();
    return request<Page<Template>>("GET", qs ? `/api/templates?${qs}` : "/api/templates");
  },
  listTemplateIDs: (q: TemplatesQuery = {}) => {
    const p = new URLSearchParams();
    if (q.source) p.set("source", q.source);
    if (q.severities?.length) p.set("severity", q.severities.join(","));
    if (q.tags?.length) p.set("tag", q.tags.join(","));
    if (q.q) p.set("q", q.q);
    if (q.sort) p.set("sort", q.sort);
    if (q.order) p.set("order", q.order);
    if (q.include_unavailable) p.set("include_unavailable", "true");
    const qs = p.toString();
    return request<{ ids: string[] }>(
      "GET",
      qs ? `/api/templates/ids?${qs}` : "/api/templates/ids",
    );
  },
  getTemplate: (id: string) =>
    request<TemplateDetail>("GET", `/api/templates/${encodeURIComponent(id)}`),
  createTemplate: (yaml: string) => requestYAML<TemplateDetail>("POST", "/api/templates", yaml),
  updateTemplate: (id: string, yaml: string) =>
    requestYAML<TemplateDetail>("PUT", `/api/templates/${encodeURIComponent(id)}`, yaml),
  deleteTemplate: (id: string) =>
    request<void>("DELETE", `/api/templates/${encodeURIComponent(id)}`),
  getTemplateSync: () => request<TemplateSyncStatus>("GET", "/api/templates/sync"),
  requestTemplateSync: () =>
    request<{ queued: boolean }>("POST", "/api/templates/sync"),
  listTemplateSyncRuns: (limit = 20, offset = 0) =>
    request<Page<TemplateSyncRun>>(
      "GET",
      `/api/templates/sync-runs?limit=${limit}&offset=${offset}`,
    ),
  templateExportURL,
  downloadTemplates: (ids: string[], format: TemplateArchiveFormat) =>
    downloadArchive(
      templateExportURL(ids, format),
      format === "yaml" ? "templates.tar.gz" : "templates.json",
    ),
  importTemplates: (file: File, conflict: TemplateImportConflict) =>
    uploadArchive("/api/templates/import", file, conflict),

  listTemplateSets: () => request<TemplateSet[]>("GET", "/api/template-sets"),
  createTemplateSet: (t: Partial<TemplateSet>) =>
    request<TemplateSet>("POST", "/api/template-sets", t),
  updateTemplateSet: (id: string, t: Partial<TemplateSet>) =>
    request<TemplateSet>("PUT", `/api/template-sets/${id}`, t),
  deleteTemplateSet: (id: string) => request<void>("DELETE", `/api/template-sets/${id}`),
  listTemplateSetMembers: (id: string) =>
    request<Template[]>("GET", `/api/template-sets/${id}/members`),
  replaceTemplateSetMembers: (id: string, templateIDs: string[]) =>
    request<TemplateSet>("PUT", `/api/template-sets/${id}/members`, {
      template_ids: templateIDs,
    }),
  addTemplateSetMembers: (id: string, templateIDs: string[]) =>
    request<TemplateSet>("POST", `/api/template-sets/${id}/members`, {
      template_ids: templateIDs,
    }),
  listTemplateSetExclusions: (id: string) =>
    request<Template[]>("GET", `/api/template-sets/${id}/exclusions`),
  replaceTemplateSetExclusions: (id: string, templateIDs: string[]) =>
    request<TemplateSet>("PUT", `/api/template-sets/${id}/exclusions`, {
      template_ids: templateIDs,
    }),
  templateSetExportURL,
  downloadTemplateSet: (id: string, format: TemplateArchiveFormat) =>
    downloadArchive(
      templateSetExportURL(id, format),
      format === "yaml" ? "template-set.tar.gz" : "template-set.json",
    ),
  importTemplateSet: (file: File, conflict: TemplateImportConflict) =>
    uploadArchive("/api/template-sets/import", file, conflict),

  // Scan policies (#87). Reads are viewer; create/edit are operator; delete is
  // admin. A null knob means "use the built-in default" for that field.
  listScanPolicies: () => request<ScanPolicy[]>("GET", "/api/scan-policies"),
  createScanPolicy: (p: Partial<ScanPolicy>) =>
    request<ScanPolicy>("POST", "/api/scan-policies", p),
  updateScanPolicy: (id: string, p: Partial<ScanPolicy>) =>
    request<ScanPolicy>("PUT", `/api/scan-policies/${id}`, p),
  deleteScanPolicy: (id: string) => request<void>("DELETE", `/api/scan-policies/${id}`),

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

  // Global app settings (#95) — admin only. The retention policy governs the
  // background scan-deletion sweeper.
  getSettings: () => request<AppSettings>("GET", "/api/settings"),
  updateSettings: (body: {
    retention_enabled: boolean;
    scan_retention_days: number | null;
    retention_include_adhoc: boolean;
  }) => request<AppSettings>("PUT", "/api/settings", body),

  listScans: () => request<Scan[]>("GET", "/api/scans"),
  getScan: (id: string) => request<Scan>("GET", `/api/scans/${id}`),
  createScan: (body: { scan_policy_id: string; target_id: string }) =>
    request<{ scan_id: string }>("POST", "/api/scans", body),
  cancelScan: (id: string) => request<void>("POST", `/api/scans/${id}/cancel`),
  deleteScan: (id: string) => request<void>("DELETE", `/api/scans/${id}`),

  listFindings: (q: FindingsQuery = {}) => {
    const p = findingsParams(q);
    if (q.limit != null) p.set("limit", String(q.limit));
    if (q.offset != null) p.set("offset", String(q.offset));
    const qs = p.toString();
    return request<Page<LifecycleFinding>>("GET", qs ? `/api/findings?${qs}` : "/api/findings");
  },
  getFinding: (id: number | string) => request<FindingDetail>("GET", `/api/findings/${id}`),
  getOccurrence: (id: number | string) => request<OccurrenceDetail>("GET", `/api/occurrences/${id}`),
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
