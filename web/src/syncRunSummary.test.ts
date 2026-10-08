import { describe, expect, it } from "vitest";
import {
  collapseSyncRuns,
  formatRefRange,
  formatSyncRunResult,
  formatSyncRunRow,
  shortDigest,
  type SyncRunSummaryInput,
} from "./syncRunSummary";

describe("shortDigest", () => {
  it("truncates to 12 characters", () => {
    expect(shortDigest("a1b2c3d4e5f67890")).toBe("a1b2c3d4e5f6");
  });

  it("renders an em dash when empty", () => {
    expect(shortDigest()).toBe("—");
    expect(shortDigest("")).toBe("—");
  });
});

describe("formatRefRange", () => {
  it("shows before → after with full values in the title", () => {
    const view = formatRefRange("aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb");
    expect(view.text).toBe("aaaaaaaaaaaa → bbbbbbbbbbbb");
    expect(view.title).toBe("aaaaaaaaaaaaaaaa → bbbbbbbbbbbbbbbb");
  });

  it("omits the arrow when ref_before is missing", () => {
    const view = formatRefRange("", "bbbbbbbbbbbbbbbb");
    expect(view.text).toBe("bbbbbbbbbbbb");
    expect(view.title).toBe("bbbbbbbbbbbbbbbb");
  });

  it("renders an em dash when both refs are empty", () => {
    expect(formatRefRange()).toEqual({ text: "—", title: "" });
  });
});

describe("formatSyncRunResult", () => {
  it("collapses a successful no-change run", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 0,
      updated: 0,
      removed: 0,
      skipped: 0,
      ref_before: "a1b2c3d4e5f67890aaaa",
      ref_after: "e4f5a6b7c8d9e0f1bbbb",
    });
    expect(view.text).toBe("No changes · a1b2c3d4e5f6 → e4f5a6b7c8d9");
    expect(view.title).toBe("a1b2c3d4e5f67890aaaa → e4f5a6b7c8d9e0f1bbbb");
  });

  it("mentions malformed files only when a no-change run skipped some", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 0,
      updated: 0,
      removed: 0,
      skipped: 7,
      ref_before: "a1b2c3d4e5f67890aaaa",
      ref_after: "e4f5a6b7c8d9e0f1bbbb",
    });
    expect(view.text).toBe(
      "No changes · a1b2c3d4e5f6 → e4f5a6b7c8d9 · 7 malformed files skipped",
    );
  });

  it("uses singular wording for one malformed file", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 0,
      updated: 0,
      removed: 0,
      skipped: 1,
      ref_before: "aaaaaaaaaaaaaaaa",
      ref_after: "bbbbbbbbbbbbbbbb",
    });
    expect(view.text).toBe(
      "No changes · aaaaaaaaaaaa → bbbbbbbbbbbb · 1 malformed file skipped",
    );
  });

  it("keeps the per-action breakdown when the catalog changed", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 2,
      updated: 1,
      removed: 3,
      skipped: 10,
      ref_before: "aaaaaaaaaaaaaaaa",
      ref_after: "bbbbbbbbbbbbbbbb",
    });
    expect(view.text).toBe("+2 / ~1 / −3 / 10 skipped");
    expect(view.title).toBe("");
  });

  it("calls out restored templates in the breakdown", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 0,
      updated: 4,
      removed: 0,
      restored: 2,
      skipped: 0,
      ref_before: "aaaaaaaaaaaaaaaa",
      ref_after: "bbbbbbbbbbbbbbbb",
    });
    expect(view.text).toBe("+0 / ~4 / 2 restored / −0 / 0 skipped");
  });

  it("treats a restored-only run as a change, not a no-op", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 0,
      updated: 0,
      removed: 0,
      restored: 4,
      skipped: 0,
      ref_before: "aaaaaaaaaaaaaaaa",
      ref_after: "aaaaaaaaaaaaaaaa",
    });
    expect(view.text).toBe("+0 / ~0 / 4 restored / −0 / 0 skipped");
  });

  it("keeps legacy rows without a restored count unchanged", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 0,
      updated: 0,
      removed: 0,
      skipped: 0,
      ref_before: "aaaaaaaaaaaaaaaa",
      ref_after: "aaaaaaaaaaaaaaaa",
    });
    expect(view.text).toBe("No changes · aaaaaaaaaaaa → aaaaaaaaaaaa");
  });

  it("does not claim no-change for a running run with zero counts", () => {
    const view = formatSyncRunResult({
      status: "running",
      added: 0,
      updated: 0,
      removed: 0,
      skipped: 0,
    });
    expect(view.text).toBe("—");
  });

  it("does not claim no-change for a failed run with zero counts", () => {
    const view = formatSyncRunResult({
      status: "failed",
      added: 0,
      updated: 0,
      removed: 0,
      skipped: 0,
      ref_after: "bbbbbbbbbbbbbbbb",
    });
    expect(view.text).toBe("—");
  });

  it("still shows counts on a failed run that changed something", () => {
    const view = formatSyncRunResult({
      status: "failed",
      added: 1,
      updated: 0,
      removed: 0,
      skipped: 4,
    });
    expect(view.text).toBe("+1 / ~0 / −0 / 4 skipped");
  });

  it("omits the empty arrow on a legacy no-change row without ref_before", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 0,
      updated: 0,
      removed: 0,
      skipped: 50,
      ref_after: "cccccccccccccccc",
    });
    expect(view.text).toBe("No changes · cccccccccccc · 50 malformed files skipped");
    expect(view.title).toBe("cccccccccccccccc");
  });

  it("omits the ref segment entirely when both refs are missing", () => {
    const view = formatSyncRunResult({
      status: "success",
      added: 0,
      updated: 0,
      removed: 0,
      skipped: 0,
    });
    expect(view.text).toBe("No changes");
    expect(view.title).toBe("");
  });
});

type Run = SyncRunSummaryInput & { id: string };

function run(id: string, over: Partial<Run> = {}): Run {
  return {
    id,
    status: "success",
    added: 0,
    updated: 0,
    removed: 0,
    skipped: 0,
    ref_before: "aaaaaaaaaaaaaaaa",
    ref_after: "aaaaaaaaaaaaaaaa",
    ...over,
  };
}

describe("collapseSyncRuns", () => {
  it("collapses a consecutive no-op series and keeps the newest run", () => {
    const groups = collapseSyncRuns([run("newest"), run("middle"), run("oldest")]);
    expect(groups).toHaveLength(1);
    expect(groups[0].count).toBe(3);
    expect(groups[0].run.id).toBe("newest");
    expect(groups[0].rest.map((r) => r.id)).toEqual(["middle", "oldest"]);
  });

  it("leaves an isolated no-op with an empty rest", () => {
    const groups = collapseSyncRuns([run("solo")]);
    expect(groups[0].count).toBe(1);
    expect(groups[0].rest).toEqual([]);
  });

  it("splits on a run that changed the catalog", () => {
    const changed = run("change", { added: 1, ref_after: "bbbbbbbbbbbbbbbb" });
    const groups = collapseSyncRuns([run("new"), changed, run("old")]);
    expect(groups.map((g) => [g.run.id, g.count])).toEqual([
      ["new", 1],
      ["change", 1],
      ["old", 1],
    ]);
  });

  it("splits when the upstream ref moved without catalog changes", () => {
    const groups = collapseSyncRuns([
      run("new", { ref_before: "bbbbbbbbbbbbbbbb", ref_after: "bbbbbbbbbbbbbbbb" }),
      run("old", { ref_before: "aaaaaaaaaaaaaaaa", ref_after: "bbbbbbbbbbbbbbbb" }),
    ]);
    expect(groups.map((g) => g.run.id)).toEqual(["new", "old"]);
  });

  it("keeps runs that skipped malformed files as their own rows", () => {
    const groups = collapseSyncRuns([run("a"), run("b", { skipped: 2 }), run("c")]);
    expect(groups.map((g) => [g.run.id, g.count])).toEqual([
      ["a", 1],
      ["b", 1],
      ["c", 1],
    ]);
  });

  it("leaves failed and running rows uncollapsed", () => {
    const groups = collapseSyncRuns([
      run("running", { status: "running" }),
      run("failed", { status: "failed" }),
      run("ok"),
    ]);
    expect(groups.map((g) => [g.run.id, g.count])).toEqual([
      ["running", 1],
      ["failed", 1],
      ["ok", 1],
    ]);
  });
});

describe("formatSyncRunRow", () => {
  it("matches formatSyncRunResult for a single run", () => {
    const single = run("solo");
    expect(formatSyncRunRow(single, 1, "anything")).toEqual(formatSyncRunResult(single));
  });

  it("appends the run count and last-checked time for a collapsed group", () => {
    const view = formatSyncRunRow(run("grouped"), 36, "10/1/2026, 6:37 PM");
    expect(view.text).toBe(
      "No changes · aaaaaaaaaaaa → aaaaaaaaaaaa · ×36, last checked 10/1/2026, 6:37 PM",
    );
    expect(view.title).toBe(
      "aaaaaaaaaaaaaaaa → aaaaaaaaaaaaaaaa · ×36, last checked 10/1/2026, 6:37 PM",
    );
  });
});
