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

export type FindingStatus = "open" | "triaged" | "false_positive" | "fixed";

export const FINDING_STATUSES: FindingStatus[] = ["open", "triaged", "false_positive", "fixed"];

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  triaged: "Triaged",
  false_positive: "False positive",
  fixed: "Fixed",
};

// LifecycleFinding is the deduplicated, triageable entity keyed on
// (target, template, matched_at). `resolved` (gone in the target's latest scan)
// and `new` (first seen in that scan) are derived server-side.
export interface LifecycleFinding {
  id: number;
  target_id?: string;
  template_id: string;
  name: string;
  severity: string;
  host: string;
  matched_at: string;
  type: string;
  cve: string[];
  tags: string[];
  status: FindingStatus;
  resolved: boolean;
  new: boolean;
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

/** view narrows the findings list: new/resolved/open are derived cuts. */
export type FindingsView = "all" | "open" | "new" | "resolved";

export interface FindingsQuery {
  targetId?: string;
  q?: string;
  severities?: string[];
  host?: string;
  cve?: string;
  tag?: string;
  status?: FindingStatus;
  view?: FindingsView;
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
  status_note?: string;
  status_by?: string;
  status_at?: string;
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
    if (q.status) p.set("status", q.status);
    if (q.view && q.view !== "all") p.set("view", q.view);
    if (q.limit != null) p.set("limit", String(q.limit));
    if (q.offset != null) p.set("offset", String(q.offset));
    const qs = p.toString();
    return request<Page<LifecycleFinding>>("GET", qs ? `/api/findings?${qs}` : "/api/findings");
  },
  getFinding: (id: number | string) => request<FindingDetail>("GET", `/api/findings/${id}`),
  updateFindingStatus: (id: number | string, body: { status: FindingStatus; note?: string }) =>
    request<FindingDetail>("PATCH", `/api/findings/${id}/status`, body),

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
