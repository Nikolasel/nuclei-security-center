import { describe, expect, it } from "vitest";
import { formatRefRange, formatSyncRunResult, shortDigest } from "./syncRunSummary";

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
