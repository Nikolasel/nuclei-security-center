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
    parts.push(`all ${run.skipped} templates skipped`);
    return { text: parts.join(" · "), title: refs.title };
  }
  return { text: actionBreakdown(run), title: "" };
}
