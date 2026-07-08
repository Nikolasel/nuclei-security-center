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

export interface Finding {
  id: number;
  scan_id: string;
  template_id: string;
  name: string;
  severity: string;
  host: string;
  matched_at: string;
  type: string;
  created_at: string;
}

export interface FindingsPage {
  items: Finding[];
  total: number;
  limit: number;
  offset: number;
}

export interface FindingsQuery {
  scanId?: string;
  severity?: string;
  host?: string;
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

export interface FindingDetail extends Finding {
  raw: NucleiRaw;
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
    if (q.scanId) p.set("scan_id", q.scanId);
    if (q.severity) p.set("severity", q.severity);
    if (q.host) p.set("host", q.host);
    if (q.limit != null) p.set("limit", String(q.limit));
    if (q.offset != null) p.set("offset", String(q.offset));
    const qs = p.toString();
    return request<FindingsPage>("GET", qs ? `/api/findings?${qs}` : "/api/findings");
  },
  getFinding: (id: number | string) => request<FindingDetail>("GET", `/api/findings/${id}`),
};
