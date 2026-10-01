// Last-used findings filter + sort. Stored per-browser as `nsc.findings.filters`,
// like `nsc.findings.columns`. Offset is intentionally not persisted: a fresh
// `/findings` load starts at page 1; an explicit `?offset=` still wins.
//
// Scan-detail occurrence filters (`ScanFindingsView`) stay in-memory — that
// list is scoped to one scan and is not the lifecycle triage view.

import type { FindingQuery } from "../api";
import { makeRow, type Row } from "./ConditionBuilder";

export const FINDINGS_FILTERS_KEY = "nsc.findings.filters";
export const FINDINGS_FILTERS_VERSION = 1;

export interface FindingsFilterPrefs {
  filter: FindingQuery;
  sort: string | null;
  order: "asc" | "desc" | null;
}

export function defaultFindingsRows(): Row[] {
  return [makeRow({ field: "state", op: "any_of", values: ["new", "active", "resurfaced"] })];
}

export function defaultFindingsFilter(): FindingQuery {
  return {
    groups: [{ conditions: [{ field: "state", op: "any_of", values: ["new", "active", "resurfaced"] }] }],
  };
}

export function defaultFindingsFilterPrefs(): FindingsFilterPrefs {
  return { filter: defaultFindingsFilter(), sort: null, order: null };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFindingQuery(value: unknown): value is FindingQuery {
  if (!isRecord(value) || !Array.isArray(value.groups)) return false;
  for (const group of value.groups) {
    if (!isRecord(group) || !Array.isArray(group.conditions)) return false;
    for (const cond of group.conditions) {
      if (!isRecord(cond) || typeof cond.field !== "string" || typeof cond.op !== "string") return false;
      if (cond.values === undefined) continue;
      if (!Array.isArray(cond.values) || cond.values.some((v) => typeof v !== "string")) return false;
    }
  }
  return true;
}

function parseOrder(value: unknown): "asc" | "desc" | null {
  return value === "asc" || value === "desc" ? value : null;
}

function parseSort(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const field = value.trim();
  return field || null;
}

/** mergeFindingsFilters applies a stored JSON value onto the prefs shape.
 *  Malformed / unknown payloads return null so the caller can use defaults. */
export function mergeFindingsFilters(raw: unknown): FindingsFilterPrefs | null {
  if (raw == null) return null;
  if (typeof raw !== "object") return null;

  // A bare FindingQuery (legacy / accidental) is accepted as a filter-only pref.
  if (isFindingQuery(raw) && !("filter" in raw) && !("v" in raw)) {
    return { filter: raw, sort: null, order: null };
  }
  if (!isRecord(raw)) return null;

  const filter = isFindingQuery(raw.filter) ? raw.filter : null;
  if (!filter) return null;

  const sort = parseSort(raw.sort);
  const order = sort ? parseOrder(raw.order) : null;
  return { filter, sort, order };
}

export function findingsFilterPrefsToStore(prefs: FindingsFilterPrefs): Record<string, unknown> {
  return {
    v: FINDINGS_FILTERS_VERSION,
    filter: prefs.filter,
    sort: prefs.sort,
    order: prefs.sort ? prefs.order : null,
  };
}

export function findingsFilterPrefsAreDefault(prefs: FindingsFilterPrefs): boolean {
  return !prefs.sort && JSON.stringify(prefs.filter) === JSON.stringify(defaultFindingsFilter());
}

export function parseFindingsFilterParam(raw: string | null): FindingQuery | undefined {
  if (raw == null || raw === "") return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (isFindingQuery(parsed)) return parsed;
  } catch {
    // malformed URL param — caller falls through to stored / defaults
  }
  return undefined;
}

/** resolveFindingsFilterPrefs: explicit URL params win, then stored, then defaults. */
export function resolveFindingsFilterPrefs(
  url: { filter: string | null; sort: string | null; order: string | null },
  storedRaw: unknown,
): FindingsFilterPrefs {
  const stored = mergeFindingsFilters(storedRaw);
  const defaults = defaultFindingsFilterPrefs();

  const urlFilter = parseFindingsFilterParam(url.filter);
  const filter = urlFilter ?? stored?.filter ?? defaults.filter;

  const urlSort = parseSort(url.sort);
  const sort = url.sort != null && url.sort !== "" ? urlSort : (stored?.sort ?? defaults.sort);
  const order =
    url.sort != null && url.sort !== ""
      ? parseOrder(url.order)
      : (stored?.order ?? defaults.order);

  return { filter, sort, order: sort ? order : null };
}

export function readStoredFindingsFilters(): unknown {
  try {
    const raw = localStorage.getItem(FINDINGS_FILTERS_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

export function writeStoredFindingsFilters(prefs: FindingsFilterPrefs): void {
  try {
    if (findingsFilterPrefsAreDefault(prefs)) {
      localStorage.removeItem(FINDINGS_FILTERS_KEY);
      return;
    }
    localStorage.setItem(FINDINGS_FILTERS_KEY, JSON.stringify(findingsFilterPrefsToStore(prefs)));
  } catch {
    // private mode / storage disabled — in-memory state still applies
  }
}

export function clearStoredFindingsFilters(): void {
  try {
    localStorage.removeItem(FINDINGS_FILTERS_KEY);
  } catch {
    // private mode / storage disabled
  }
}
