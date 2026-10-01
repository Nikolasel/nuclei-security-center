/** First 12 hex chars of a git digest, or an em dash when empty. */
export function shortDigest(value?: string) {
  return value ? value.slice(0, 12) : "—";
}

export type SyncRunSummaryInput = {
  status: string;
  added: number;
  updated: number;
  removed: number;
  skipped: number;
  ref_before?: string;
  ref_after?: string;
};

export type SyncRunSummaryView = {
  text: string;
  title: string;
};

function trimRef(value?: string): string {
  return value?.trim() ?? "";
}

/** from → to using short digests; omits a dangling arrow when a side is missing. */
export function formatRefRange(before?: string, after?: string): SyncRunSummaryView {
  const from = trimRef(before);
  const to = trimRef(after);
  if (from && to) {
    return { text: `${shortDigest(from)} → ${shortDigest(to)}`, title: `${from} → ${to}` };
  }
  if (to) return { text: shortDigest(to), title: to };
  if (from) return { text: shortDigest(from), title: from };
  return { text: "—", title: "" };
}

function actionBreakdown(run: SyncRunSummaryInput): string {
  return `+${run.added} / ~${run.updated} / −${run.removed} / ${run.skipped} skipped`;
}

function isNoChange(run: SyncRunSummaryInput): boolean {
  return run.added === 0 && run.updated === 0 && run.removed === 0;
}

function malformedSkipped(count: number): string {
  const noun = count === 1 ? "file" : "files";
  return `${count} malformed ${noun} skipped`;
}

/** A silent no-op refresh: nothing changed and nothing was skipped. */
function isSilentNoChange(run: SyncRunSummaryInput): boolean {
  return run.status === "success" && isNoChange(run) && run.skipped === 0;
}

function sameRefs(a: SyncRunSummaryInput, b: SyncRunSummaryInput): boolean {
  return trimRef(a.ref_before) === trimRef(b.ref_before) && trimRef(a.ref_after) === trimRef(b.ref_after);
}

export type SyncRunGroup<T> = { run: T; count: number; rest: T[] };

/**
 * Collapses consecutive identical no-op refreshes so a long series of periodic
 * checks reads as one history row. Input is expected newest-first (the API
 * order); each group keeps its newest run in `run` and the older members in
 * `rest`. A catalog change, failure, running row, malformed-skip row, or a
 * moved upstream ref starts a new group.
 */
export function collapseSyncRuns<T extends SyncRunSummaryInput>(runs: T[]): SyncRunGroup<T>[] {
  const groups: SyncRunGroup<T>[] = [];
  for (const run of runs) {
    const prev = groups[groups.length - 1];
    if (prev && isSilentNoChange(prev.run) && isSilentNoChange(run) && sameRefs(prev.run, run)) {
      prev.count += 1;
      prev.rest.push(run);
      continue;
    }
    groups.push({ run, count: 1, rest: [] });
  }
  return groups;
}

/** Result cell for one history row — a single run, or a collapsed group of them. */
export function formatSyncRunRow(
  run: SyncRunSummaryInput,
  count: number,
  lastChecked: string,
): SyncRunSummaryView {
  const view = formatSyncRunResult(run);
  if (count <= 1) return view;
  const suffix = `×${count}, last checked ${lastChecked}`;
  return {
    text: `${view.text} · ${suffix}`,
    title: view.title ? `${view.title} · ${suffix}` : suffix,
  };
}

/**
 * Result cell for a template sync run. Successful no-op refreshes collapse to a
 * single sentence; runs that changed the catalog keep the +/~/-/skipped counts.
 * Running and failed rows (and legacy rows without ref_before) stay readable.
 */
export function formatSyncRunResult(run: SyncRunSummaryInput): SyncRunSummaryView {
  if (run.status === "running") {
    return { text: "—", title: "" };
  }
  if (run.status === "failed") {
    if (!isNoChange(run)) return { text: actionBreakdown(run), title: "" };
    return { text: "—", title: "" };
  }
  if (run.status === "success" && isNoChange(run)) {
    const refs = formatRefRange(run.ref_before, run.ref_after);
    const parts = ["No changes"];
    if (refs.text !== "—") parts.push(refs.text);
    if (run.skipped > 0) parts.push(malformedSkipped(run.skipped));
    return { text: parts.join(" · "), title: refs.title };
  }
  return { text: actionBreakdown(run), title: "" };
}
