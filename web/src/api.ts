// Typed client for the backend JSON API (served same-origin under /api). Auth is
// the BFF session cookie, so every request is credentialed and no tokens are
// handled here.

export interface Identity {
  subject: string;
  email?: string;
  name?: string;
  roles: string[];
}

export interface Target {
  id: string;
  name: string;
  hosts: string[];
  tags: string[];
  created_by?: string;
  created_at: string;
  updated_at: string;
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
  next_run_at?: string;
  last_run_at?: string;
  last_scan_id?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export type ScanState = "queued" | "running" | "complete" | "failed";

export interface Scan {
  id: string;
  state: ScanState;
  nuclei_version?: string;
  templates_commit?: string;
  error?: string;
  created_at: string;
  finished_at?: string;
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

  listScans: () => request<Scan[]>("GET", "/api/scans"),
  getScan: (id: string) => request<Scan>("GET", `/api/scans/${id}`),
  createScan: (body: { target_id?: string; template_set_id?: string }) =>
    request<{ scan_id: string }>("POST", "/api/scans", body),

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
