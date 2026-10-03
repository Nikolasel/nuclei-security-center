import { afterEach, describe, expect, it } from "vitest";
import { rowsToQuery } from "./ConditionBuilder";
import {
  FINDINGS_FILTERS_KEY,
  FINDINGS_PRESETS,
  matchFindingsPreset,
  FINDINGS_FILTERS_VERSION,
  clearStoredFindingsFilters,
  defaultFindingsFilter,
  defaultFindingsFilterPrefs,
  findingsFilterPrefsAreDefault,
  findingsFilterPrefsToStore,
  mergeFindingsFilters,
  parseFindingsFilterParam,
  readStoredFindingsFilters,
  resolveFindingsFilterPrefs,
  writeStoredFindingsFilters,
  type FindingsFilterPrefs,
} from "./findingsFilters";

const customFilter = {
  groups: [{ conditions: [{ field: "name", op: "contains", values: ["ssl"] }] }],
};

const customPrefs: FindingsFilterPrefs = {
  filter: customFilter,
  sort: "severity",
  order: "desc",
};

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() {
      return data.size;
    },
    clear() {
      data.clear();
    },
    getItem(key: string) {
      return data.get(key) ?? null;
    },
    key(index: number) {
      return [...data.keys()][index] ?? null;
    },
    removeItem(key: string) {
      data.delete(key);
    },
    setItem(key: string, value: string) {
      data.set(key, value);
    },
  };
}

afterEach(() => {
  Reflect.deleteProperty(globalThis, "localStorage");
});

describe("mergeFindingsFilters", () => {
  it("returns null for missing or malformed payloads", () => {
    expect(mergeFindingsFilters(null)).toBeNull();
    expect(mergeFindingsFilters(undefined)).toBeNull();
    expect(mergeFindingsFilters("not-json-object")).toBeNull();
    expect(mergeFindingsFilters([])).toBeNull();
    expect(mergeFindingsFilters({ filter: { groups: "nope" } })).toBeNull();
    expect(mergeFindingsFilters({ filter: { groups: [{ conditions: [{ field: 1, op: "any_of" }] }] } })).toBeNull();
    expect(mergeFindingsFilters({ filter: { groups: [{ conditions: [{ field: "state", op: "any_of", values: [1] }] }] } })).toBeNull();
  });

  it("round-trips a versioned store object and drops a sort without a field", () => {
    const stored = findingsFilterPrefsToStore(customPrefs);
    expect(stored.v).toBe(FINDINGS_FILTERS_VERSION);
    expect(mergeFindingsFilters(stored)).toEqual(customPrefs);
    expect(mergeFindingsFilters({ ...stored, extra: true, order: "sideways" })).toEqual({
      ...customPrefs,
      order: null,
    });
  });

  it("accepts a bare FindingQuery as a legacy filter-only payload", () => {
    expect(mergeFindingsFilters(customFilter)).toEqual({
      filter: customFilter,
      sort: null,
      order: null,
    });
  });
});

describe("resolveFindingsFilterPrefs", () => {
  const stored = findingsFilterPrefsToStore(customPrefs);

  it("uses defaults when nothing is provided", () => {
    expect(resolveFindingsFilterPrefs({ filter: null, sort: null, order: null }, null)).toEqual(
      defaultFindingsFilterPrefs(),
    );
  });

  it("uses stored prefs when the URL has no explicit params", () => {
    expect(resolveFindingsFilterPrefs({ filter: null, sort: null, order: null }, stored)).toEqual(customPrefs);
  });

  it("lets explicit URL params override stored prefs", () => {
    const urlFilter = {
      groups: [{ conditions: [{ field: "severity", op: "any_of", values: ["critical"] }] }],
    };
    expect(
      resolveFindingsFilterPrefs(
        { filter: JSON.stringify(urlFilter), sort: "name", order: "asc" },
        stored,
      ),
    ).toEqual({ filter: urlFilter, sort: "name", order: "asc" });
  });

  it("falls back to stored then defaults when the URL filter is malformed", () => {
    expect(resolveFindingsFilterPrefs({ filter: "{", sort: null, order: null }, stored)).toEqual({
      filter: customPrefs.filter,
      sort: customPrefs.sort,
      order: customPrefs.order,
    });
    expect(resolveFindingsFilterPrefs({ filter: "{", sort: null, order: null }, "garbage")).toEqual(
      defaultFindingsFilterPrefs(),
    );
  });

  it("keeps stored sort when only the filter is in the URL", () => {
    const urlFilter = defaultFindingsFilter();
    expect(
      resolveFindingsFilterPrefs({ filter: JSON.stringify(urlFilter), sort: null, order: null }, stored),
    ).toEqual({ filter: urlFilter, sort: "severity", order: "desc" });
  });
});

describe("parseFindingsFilterParam", () => {
  it("returns undefined for absent, empty, or malformed values", () => {
    expect(parseFindingsFilterParam(null)).toBeUndefined();
    expect(parseFindingsFilterParam("")).toBeUndefined();
    expect(parseFindingsFilterParam("not-json")).toBeUndefined();
    expect(parseFindingsFilterParam(JSON.stringify({ groups: [] }))).toEqual({ groups: [] });
  });
});

describe("localStorage read/write", () => {
  it("round-trips non-default prefs and clears the key for defaults", () => {
    globalThis.localStorage = memoryStorage();
    writeStoredFindingsFilters(customPrefs);
    expect(JSON.parse(localStorage.getItem(FINDINGS_FILTERS_KEY) ?? "")).toEqual(
      findingsFilterPrefsToStore(customPrefs),
    );
    expect(mergeFindingsFilters(readStoredFindingsFilters())).toEqual(customPrefs);

    writeStoredFindingsFilters(defaultFindingsFilterPrefs());
    expect(localStorage.getItem(FINDINGS_FILTERS_KEY)).toBeNull();
    expect(findingsFilterPrefsAreDefault(defaultFindingsFilterPrefs())).toBe(true);

    writeStoredFindingsFilters(customPrefs);
    clearStoredFindingsFilters();
    expect(localStorage.getItem(FINDINGS_FILTERS_KEY)).toBeNull();
    expect(readStoredFindingsFilters()).toBeNull();
  });

  it("treats an empty filter (clear-all) as a stored preference, not the default", () => {
    const empty: FindingsFilterPrefs = { filter: { groups: [] }, sort: null, order: null };
    expect(findingsFilterPrefsAreDefault(empty)).toBe(false);
    globalThis.localStorage = memoryStorage();
    writeStoredFindingsFilters(empty);
    expect(mergeFindingsFilters(readStoredFindingsFilters())).toEqual(empty);
  });

  it("degrades when localStorage throws or contains invalid JSON", () => {
    globalThis.localStorage = {
      ...memoryStorage(),
      getItem() {
        throw new Error("blocked");
      },
      setItem() {
        throw new Error("blocked");
      },
      removeItem() {
        throw new Error("blocked");
      },
    };
    expect(readStoredFindingsFilters()).toBeNull();
    expect(() => writeStoredFindingsFilters(customPrefs)).not.toThrow();
    expect(() => clearStoredFindingsFilters()).not.toThrow();

    globalThis.localStorage = memoryStorage();
    localStorage.setItem(FINDINGS_FILTERS_KEY, "{not json");
    expect(readStoredFindingsFilters()).toBeNull();
    localStorage.setItem(FINDINGS_FILTERS_KEY, JSON.stringify({ nope: true }));
    expect(mergeFindingsFilters(readStoredFindingsFilters())).toBeNull();
  });
});

describe("findings presets", () => {
  const now = new Date("2026-10-03T12:00:00Z");
  const compiled = (id: string) => rowsToQuery(FINDINGS_PRESETS.find((p) => p.id === id)!.rows(now));

  it("treats the default filter as the open preset", () => {
    expect(matchFindingsPreset(defaultFindingsFilter(), now)?.id).toBe("open");
  });

  it("recognizes each preset's own filter", () => {
    for (const p of FINDINGS_PRESETS) expect(matchFindingsPreset(compiled(p.id), now)?.id).toBe(p.id);
  });

  it("returns null for a customized filter", () => {
    const custom = { groups: [{ conditions: [{ field: "severity", op: "any_of", values: ["high"] }] }] };
    expect(matchFindingsPreset(custom, now)).toBeNull();
  });
});
