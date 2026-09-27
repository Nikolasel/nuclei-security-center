// Findings list columns. Visibility and widths are a per-browser preference
// (`nsc.findings.columns`), like `nsc.theme` and `nsc.nav.collapsed`.
// Filters stay in the URL.
//
// The stored value is an object keyed by column id. Each entry is
// `{ visible, width? }`. On read, unknown ids are dropped, missing ids take
// the catalog default, and a numeric width is clamped into that column's
// range so a stale value (for example 5000) cannot blow out the layout. A
// missing or non-numeric width falls back to the catalog width. A column
// added later shows up when its catalog default is visible, instead of
// inheriting a stale "hide everything I don't know" preference.

export const FINDINGS_COLUMNS_KEY = "nsc.findings.columns";

/** Drag floor for Endpoint. A protocol pill plus host and path needs more than
 *  the 72–96px floors used by the other columns. */
export const ENDPOINT_MIN_PX = 240;

/** Minimum width of the trailing filler column. It absorbs leftover table
 *  width so every real column keeps a stored pixel width. The table scrolls
 *  once the real widths plus this floor exceed the container. */
export const FINDINGS_FILLER_MIN_PX = 24;

export type FindingsColumnId =
  | "severity"
  | "finding"
  | "state"
  | "endpoint"
  | "last_seen"
  | "target"
  | "first_seen"
  | "cve"
  | "tags"
  | "matched_at"
  | "result_identity";

export interface FindingsColumn {
  id: FindingsColumnId;
  label: string;
  defaultVisible: boolean;
  /** Fixed layout width in px. Leftover table width goes to the filler column. */
  width?: number;
  /** Inclusive drag and keyboard range. */
  minWidth?: number;
  maxWidth?: number;
  /** `sort` query values that refer to this column (#311). Hiding the column
   *  clears that sort so the list order is not unexplained. */
  sortFields: readonly string[];
}

// Floors sit in the 72–96px range: short labels near 72, content columns at 96.
// Endpoint's floor is ENDPOINT_MIN_PX. maxWidth is what a stored 5000px preference clamps to.
// Every catalog column has a pixel width. A filler column after the last real
// one absorbs leftover table width.
export const FINDINGS_COLUMNS: readonly FindingsColumn[] = [
  { id: "severity", label: "Severity", defaultVisible: true, width: 112, minWidth: 80, maxWidth: 240, sortFields: ["severity", "effective_severity"] },
  { id: "finding", label: "Finding", defaultVisible: true, width: 320, minWidth: 96, maxWidth: 640, sortFields: ["name", "template_id"] },
  { id: "state", label: "State", defaultVisible: true, width: 140, minWidth: 72, maxWidth: 240, sortFields: ["state", "effective_state", "detection_state"] },
  { id: "endpoint", label: "Endpoint", defaultVisible: true, width: 320, minWidth: ENDPOINT_MIN_PX, maxWidth: 640, sortFields: ["host", "type"] },
  { id: "last_seen", label: "Last seen", defaultVisible: true, width: 112, minWidth: 96, maxWidth: 240, sortFields: ["last_seen_at", "last_seen"] },
  { id: "target", label: "Target", defaultVisible: false, width: 168, minWidth: 80, maxWidth: 420, sortFields: ["target", "target_id"] },
  { id: "first_seen", label: "First seen", defaultVisible: false, width: 112, minWidth: 96, maxWidth: 240, sortFields: ["first_seen_at", "first_seen"] },
  { id: "cve", label: "CVE", defaultVisible: false, width: 168, minWidth: 72, maxWidth: 420, sortFields: ["cve"] },
  { id: "tags", label: "Tags", defaultVisible: false, width: 180, minWidth: 72, maxWidth: 420, sortFields: ["tags", "tag"] },
  { id: "matched_at", label: "Matched at", defaultVisible: false, width: 280, minWidth: 96, maxWidth: 640, sortFields: ["matched_at"] },
  { id: "result_identity", label: "Result identity", defaultVisible: false, width: 280, minWidth: 96, maxWidth: 640, sortFields: ["matcher_name", "extractor_name", "extracted_results"] },
];

export interface FindingsColumnPref {
  visible: boolean;
  /** Clamped px width. Omitted from storage when it matches the catalog width. */
  width?: number;
}

export type FindingsColumnPrefs = Record<FindingsColumnId, FindingsColumnPref>;

const COLUMN_BY_ID = new Map(FINDINGS_COLUMNS.map((col) => [col.id, col]));

interface StoredColumn {
  visible: boolean;
  width?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function storedVisible(entry: unknown, fallback: boolean): boolean {
  if (typeof entry === "boolean") return entry;
  if (isRecord(entry) && typeof entry.visible === "boolean") return entry.visible;
  return fallback;
}

function columnBounds(col: FindingsColumn): { min: number; max: number } | null {
  if (col.width == null || col.minWidth == null || col.maxWidth == null) return null;
  return { min: col.minWidth, max: col.maxWidth };
}

/** clampColumnWidth limits a drag or key step to the column's range. */
export function clampColumnWidth(id: FindingsColumnId, width: number): number | null {
  const col = COLUMN_BY_ID.get(id);
  if (!col) return null;
  const bounds = columnBounds(col);
  if (!bounds || !Number.isFinite(width)) return null;
  return Math.round(Math.min(bounds.max, Math.max(bounds.min, width)));
}

function widthFromStored(col: FindingsColumn, entry: unknown): number | undefined {
  const bounds = columnBounds(col);
  if (!bounds || col.width == null) return undefined;
  const raw = isRecord(entry) ? entry.width : undefined;
  if (typeof raw !== "number" || !Number.isFinite(raw)) return col.width;
  return Math.round(Math.min(bounds.max, Math.max(bounds.min, raw)));
}

function prefFor(col: FindingsColumn, entry: unknown, visibleFallback: boolean): FindingsColumnPref {
  const visible = storedVisible(entry, visibleFallback);
  const width = widthFromStored(col, entry);
  return width == null ? { visible } : { visible, width };
}

/** mergeFindingsColumns applies a stored preference object onto the catalog. */
export function mergeFindingsColumns(raw: unknown): FindingsColumnPrefs {
  const stored = isRecord(raw) ? raw : {};
  const prefs = {} as FindingsColumnPrefs;
  for (const col of FINDINGS_COLUMNS) {
    prefs[col.id] = prefFor(col, stored[col.id], col.defaultVisible);
  }
  // A preference that hides every column is unusable. Treat it as "no
  // preference" and restore the catalog defaults, widths included.
  if (!FINDINGS_COLUMNS.some((col) => prefs[col.id].visible)) {
    for (const col of FINDINGS_COLUMNS) prefs[col.id] = prefFor(col, undefined, col.defaultVisible);
  }
  return prefs;
}

/** columnPrefsToStore rebuilds the preference object from the catalog. Unknown
 *  ids are dropped. A width equal to the catalog width is omitted, and
 *  `dropWidths` omits every width — Reset to defaults uses that so a dragged
 *  width does not survive a visibility reset. */
export function columnPrefsToStore(
  prefs: FindingsColumnPrefs,
  options?: { dropWidths?: boolean },
): Record<string, StoredColumn> {
  const next: Record<string, StoredColumn> = {};
  for (const col of FINDINGS_COLUMNS) {
    const entry: StoredColumn = { visible: prefs[col.id].visible };
    const width = prefs[col.id].width;
    if (
      !options?.dropWidths &&
      typeof width === "number" &&
      Number.isFinite(width) &&
      width !== col.width
    ) {
      entry.width = width;
    }
    next[col.id] = entry;
  }
  return next;
}

export function readStoredFindingsColumns(): unknown {
  try {
    const raw = localStorage.getItem(FINDINGS_COLUMNS_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

export function writeStoredFindingsColumns(prefs: FindingsColumnPrefs, options?: { dropWidths?: boolean }): void {
  try {
    const next = columnPrefsToStore(prefs, options);
    localStorage.setItem(FINDINGS_COLUMNS_KEY, JSON.stringify(next));
  } catch {
    // private mode / storage disabled — the in-memory choice still applies.
  }
}

/** sortField pulls the allowlisted field out of a `sort` query value.
 *  Accepts `field`, `field:desc`, and a leading `+` / `-`. */
export function sortField(sort: string | null): string {
  if (!sort) return "";
  let field = sort.trim();
  if (field.startsWith("+") || field.startsWith("-")) field = field.slice(1).trim();
  const colon = field.indexOf(":");
  if (colon >= 0) field = field.slice(0, colon).trim();
  return field;
}

export function columnIdForSort(sort: string | null): FindingsColumnId | null {
  const field = sortField(sort);
  if (!field) return null;
  const col = FINDINGS_COLUMNS.find((c) => c.sortFields.includes(field));
  return col?.id ?? null;
}

/** visibleFindingsColumns is the catalog order, with a hidden sort column
 *  forced on so the row order has a visible cause. Every returned column keeps
 *  a pixel width; leftover table width belongs to the filler column. */
export function visibleFindingsColumns(prefs: FindingsColumnPrefs, sort: string | null): FindingsColumn[] {
  const sortColumn = columnIdForSort(sort);
  return FINDINGS_COLUMNS.filter((c) => prefs[c.id].visible || c.id === sortColumn);
}

export function findingsTableMinWidth(columns: readonly FindingsColumn[], prefs: FindingsColumnPrefs): number {
  const real = columns.reduce((sum, col) => sum + (prefs[col.id].width ?? col.width ?? 0), 0);
  return real + FINDINGS_FILLER_MIN_PX;
}

export interface ColumnResizeTarget {
  id: FindingsColumnId;
  label: string;
  width: number;
  min: number;
  max: number;
}

/** resizeHandleFor is the separator on the right edge of `columns[hostIndex]`.
 *  That boundary resizes the column on its left. The filler column is not in
 *  `columns`, so every real column has a handle and the filler has none. */
export function resizeHandleFor(
  columns: readonly FindingsColumn[],
  hostIndex: number,
  prefs: FindingsColumnPrefs,
): ColumnResizeTarget | null {
  if (hostIndex < 0 || hostIndex >= columns.length) return null;
  const host = columns[hostIndex];
  if (!host?.width) return null;
  const bounds = columnBounds(host);
  if (!bounds) return null;
  return {
    id: host.id,
    label: host.label,
    width: prefs[host.id].width ?? host.width,
    min: bounds.min,
    max: bounds.max,
  };
}

export interface EndpointParts {
  protocol: string;
  hostport: string;
  path: string;
  /** Full matched URL (or the host) for the cell title. */
  title: string;
}

/** endpointParts splits a Nuclei matched-at value into the triage endpoint:
 *  protocol pill, host:port, and the path (including query and fragment). */
export function endpointParts(matchedAt: string, host: string, type: string): EndpointParts {
  const raw = matchedAt.trim();
  const fallbackHost = host.trim();
  const fallbackProtocol = type.trim();
  const title = raw || fallbackHost;

  const parsed = parseUrlEndpoint(raw);
  if (parsed) {
    return {
      protocol: parsed.protocol || fallbackProtocol,
      hostport: parsed.hostport || fallbackHost,
      path: parsed.path,
      title,
    };
  }

  const split = splitAuthorityPath(raw);
  if (split) {
    return {
      protocol: fallbackProtocol,
      hostport: split.hostport || fallbackHost,
      path: split.path,
      title,
    };
  }

  return { protocol: fallbackProtocol, hostport: fallbackHost, path: "", title };
}

function parseUrlEndpoint(raw: string): { protocol: string; hostport: string; path: string } | null {
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  const protocol = url.protocol.replace(/:$/, "");
  // file:// and other host-less URLs have no authority. Returning null would
  // re-parse the scheme as a host ("file:" + "///opt/...").
  if (!url.hostname) {
    return {
      protocol,
      hostport: "",
      path: formatPath(url.pathname, url.search, url.hash),
    };
  }
  return {
    protocol,
    hostport: url.host,
    path: formatPath(url.pathname, url.search, url.hash),
  };
}

function formatPath(pathname: string, search: string, hash: string): string {
  if (pathname === "" || pathname === "/") {
    if (!search && !hash) return "";
    return `/${search}${hash}`;
  }
  return `${pathname}${search}${hash}`;
}

function splitAuthorityPath(raw: string): { hostport: string; path: string } | null {
  if (!raw) return null;
  const idx = raw.search(/[/?#]/);
  if (idx < 0) return { hostport: raw, path: "" };
  const authority = raw.slice(0, idx).trim();
  const rest = raw.slice(idx);
  let path = "";
  if (rest.startsWith("/")) path = rest === "/" ? "" : rest;
  else if (rest.startsWith("?") || rest.startsWith("#")) path = `/${rest}`;
  if (!authority && !path) return null;
  return { hostport: authority, path };
}

export interface ResultIdentityFields {
  matcher_name?: string;
  extractor_name?: string;
  extracted_results?: string[];
}

/** resultIdentityLine is the unlabeled compact tuple shown under Finding
 *  (and in the Result identity column). Empty when none of the three parts
 *  are present. */
export function resultIdentityLine(finding: ResultIdentityFields): string {
  const bits: string[] = [];
  if (finding.matcher_name) bits.push(finding.matcher_name);
  if (finding.extractor_name) bits.push(finding.extractor_name);
  if (finding.extracted_results?.length) bits.push(finding.extracted_results.join(", "));
  return bits.join(" · ");
}

/** resultIdentityTitle labels each part so a hover matches the detail page
 *  (matcher / extractor / extracted) without spending list-cell space. */
export function resultIdentityTitle(finding: ResultIdentityFields): string {
  const bits: string[] = [];
  if (finding.matcher_name) bits.push(`matcher: ${finding.matcher_name}`);
  if (finding.extractor_name) bits.push(`extractor: ${finding.extractor_name}`);
  if (finding.extracted_results?.length) bits.push(`extracted: ${finding.extracted_results.join(", ")}`);
  return bits.join(" · ");
}
