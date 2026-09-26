import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Columns3, Filter } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ExportFormat, type LifecycleFinding } from "../api";
import {
  ConditionBuilder,
  countActiveConditions,
  makeRow,
  queryToRows,
  rowsToCrumbs,
  rowsToQuery,
  type Row,
} from "./ConditionBuilder";
import { type Option } from "./filters";
import {
  clampColumnWidth,
  columnIdForSort,
  endpointParts,
  resizeHandleFor,
  sortField,
  FINDINGS_COLUMNS,
  FINDINGS_COLUMNS_KEY,
  findingsTableMinWidth,
  mergeFindingsColumns,
  readStoredFindingsColumns,
  visibleFindingsColumns,
  writeStoredFindingsColumns,
  type ColumnResizeTarget,
  type FindingsColumnId,
  type FindingsColumnPrefs,
} from "./findingsColumns";
import { Button, Card, cn, ErrorText, FindingStateBadge, Pill, SeverityBadge, Spinner } from "./ui";

const EXPORT_FORMATS: { format: ExportFormat; label: string }[] = [
  { format: "json", label: "JSON" },
  { format: "csv", label: "CSV" },
  { format: "sarif", label: "SARIF" },
  { format: "raw", label: "Raw (JSONL)" },
];

const PAGE_SIZE = 50;

// The default view shows the findings that still need attention — currently
// detected states (New / Active / Resurfaced) — hiding the resolved ones
// (Mitigated / Previously mitigated) and the handled overlays (Accepted / False
// positive). Resurfaced is the "was mitigated, detected again" case, so it stays.
const defaultRows = (): Row[] => [makeRow({ field: "state", op: "any_of", values: ["new", "active", "resurfaced"] })];

function relTime(iso: string): string {
  const d = new Date(iso).getTime();
  if (Number.isNaN(d)) return "—";
  const secs = Math.round((Date.now() - d) / 1000);
  if (secs < 60) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  return `${days}d ago`;
}

const AUTO_MITIGATION_NOTE =
  "Auto-mitigation unavailable: no network host:port, so scan absence cannot automatically mark this finding mitigated";

const columnMenuCls =
  "z-50 max-h-80 min-w-56 overflow-y-auto rounded-md border border-neutral-200 bg-white p-1 shadow-lg dark:border-neutral-800 dark:bg-neutral-900";
const columnItemCls =
  "flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm outline-none hover:bg-neutral-100 dark:hover:bg-neutral-800";

const RESIZE_STEP_PX = 8;
const RESIZE_PAGE_STEP_PX = 32;

function ColumnResizeHandle({
  target,
  onPreview,
  onCommit,
  onReset,
}: {
  target: ColumnResizeTarget;
  onPreview: (id: FindingsColumnId, width: number) => void;
  onCommit: (id: FindingsColumnId, width: number) => void;
  onReset: (id: FindingsColumnId) => void;
}) {
  const drag = useRef<{
    pointerId: number;
    id: FindingsColumnId;
    startX: number;
    startWidth: number;
    latest: number;
  } | null>(null);

  const finish = () => {
    const current = drag.current;
    if (!current) return;
    drag.current = null;
    if (current.latest !== current.startWidth) onCommit(current.id, current.latest);
  };

  const nudge = (next: number) => {
    const clamped = clampColumnWidth(target.id, next);
    if (clamped == null) return;
    onCommit(target.id, clamped);
  };

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={`Resize ${target.label} column`}
      aria-valuemin={target.min}
      aria-valuemax={target.max}
      aria-valuenow={target.width}
      tabIndex={0}
      title="Drag to resize. Double-click to reset."
      className="group absolute inset-y-0 right-0 z-20 w-3 cursor-col-resize touch-none select-none focus-visible:outline-none"
      onPointerDown={(e) => {
        if (e.button !== 0) return;
        e.stopPropagation();
        e.currentTarget.setPointerCapture(e.pointerId);
        drag.current = {
          pointerId: e.pointerId,
          id: target.id,
          startX: e.clientX,
          startWidth: target.width,
          latest: target.width,
        };
      }}
      onPointerMove={(e) => {
        const current = drag.current;
        if (!current || current.pointerId !== e.pointerId) return;
        const next = clampColumnWidth(current.id, current.startWidth + (e.clientX - current.startX));
        if (next == null || next === current.latest) return;
        current.latest = next;
        onPreview(current.id, next);
      }}
      onPointerUp={(e) => {
        if (!drag.current || drag.current.pointerId !== e.pointerId) return;
        finish();
      }}
      onPointerCancel={() => finish()}
      onLostPointerCapture={() => finish()}
      onDoubleClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        drag.current = null;
        onReset(target.id);
      }}
      onKeyDown={(e) => {
        const step = e.shiftKey ? RESIZE_PAGE_STEP_PX : RESIZE_STEP_PX;
        if (e.key === "ArrowLeft" || e.key === "ArrowDown") {
          e.preventDefault();
          nudge(target.width - step);
        } else if (e.key === "ArrowRight" || e.key === "ArrowUp") {
          e.preventDefault();
          nudge(target.width + step);
        } else if (e.key === "Home") {
          e.preventDefault();
          nudge(target.min);
        } else if (e.key === "End") {
          e.preventDefault();
          nudge(target.max);
        }
      }}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-y-1 left-1/2 w-px -translate-x-1/2 bg-neutral-300 group-hover:w-0.5 group-hover:bg-indigo-500 group-focus-visible:w-0.5 group-focus-visible:bg-indigo-500 dark:bg-neutral-600"
      />
    </div>
  );
}

function EmptyMark() {
  return <span className="text-neutral-300 dark:text-neutral-600">—</span>;
}

function timeTitle(iso: string): string | undefined {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? undefined : d.toLocaleString();
}

function CveChip({ cves }: { cves: string[] }) {
  if (!cves.length) return null;
  return (
    <span className="inline-flex shrink-0 items-center" title={cves.join(", ")}>
      <span className="max-w-[7.5rem] truncate rounded bg-red-50 px-1.5 py-0.5 font-mono text-[11px] text-red-700 dark:bg-red-950/50 dark:text-red-300">
        {cves[0]}
      </span>
      {cves.length > 1 && (
        <span className="ml-1 font-mono text-[11px] text-red-700 dark:text-red-300">+{cves.length - 1}</span>
      )}
    </span>
  );
}

function EndpointCell({ finding }: { finding: LifecycleFinding }) {
  const parts = endpointParts(finding.matched_at, finding.host, finding.type);
  if (!parts.hostport && !parts.path) return <EmptyMark />;
  return (
    <div className="flex min-w-0 max-w-full items-center gap-1.5" title={parts.title || undefined}>
      {parts.protocol && (
        <span className="shrink-0 rounded bg-neutral-100 px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wide text-neutral-600 dark:bg-neutral-800 dark:text-neutral-300">
          {parts.protocol}
        </span>
      )}
      <span className="min-w-0 truncate">
        {parts.hostport}
        {parts.path && (
          <span className="font-mono text-neutral-600 dark:text-neutral-300">
            {parts.hostport ? " " : ""}
            {parts.path}
          </span>
        )}
      </span>
    </div>
  );
}

function TargetCell({ ids, names }: { ids: string[]; names: Map<string, string> }) {
  if (!ids.length) return <EmptyMark />;
  const label = ids.map((id) => names.get(id) ?? id).join(", ");
  return (
    <div className="max-w-full truncate" title={label}>
      {ids.map((id, i) => (
        <span key={id}>
          {i > 0 ? ", " : null}
          <Link
            to={`/targets?target=${encodeURIComponent(id)}`}
            title={id}
            onClick={(e) => e.stopPropagation()}
            className="text-indigo-600 hover:underline dark:text-indigo-400"
          >
            {names.get(id) ?? id}
          </Link>
        </span>
      ))}
    </div>
  );
}

function FindingCell({ finding }: { finding: LifecycleFinding }) {
  const cves = finding.cve ?? [];
  return (
    <div className="flex min-w-0 max-w-full items-center gap-1.5">
      <span className="min-w-0 truncate" title={finding.name || undefined}>
        {finding.name || <EmptyMark />}
      </span>
      {finding.times_mitigated > 0 && (
        <span className="shrink-0" title="Times gone then re-observed">
          <Pill tone="warn">↻ {finding.times_mitigated}</Pill>
        </span>
      )}
      <CveChip cves={cves} />
    </div>
  );
}

function TagsCell({ tags }: { tags: string[] }) {
  if (!tags.length) return <EmptyMark />;
  return (
    <div className="flex max-w-full gap-1 overflow-hidden" title={tags.join(", ")}>
      {tags.map((tag) => (
        <span
          key={tag}
          className="shrink-0 rounded bg-neutral-100 px-1.5 py-0.5 font-mono text-[11px] text-neutral-700 dark:bg-neutral-800 dark:text-neutral-200"
        >
          {tag}
        </span>
      ))}
    </div>
  );
}

function TimeCell({ iso }: { iso: string }) {
  return (
    <span className="text-xs text-neutral-500" title={timeTitle(iso)}>
      {relTime(iso)}
    </span>
  );
}

function FindingCellSwitch({
  id,
  finding,
  targetNames,
}: {
  id: FindingsColumnId;
  finding: LifecycleFinding;
  targetNames: Map<string, string>;
}) {
  switch (id) {
    case "severity":
      return <SeverityBadge severity={finding.effective_severity} recast={!!finding.recast_severity} />;
    case "finding":
      return <FindingCell finding={finding} />;
    case "state":
      return (
        <FindingStateBadge
          state={finding.effective_state}
          description={finding.auto_mitigation_eligible ? undefined : AUTO_MITIGATION_NOTE}
        />
      );
    case "endpoint":
      return <EndpointCell finding={finding} />;
    case "last_seen":
      return <TimeCell iso={finding.last_seen_at} />;
    case "target":
      return <TargetCell ids={finding.target_ids ?? []} names={targetNames} />;
    case "first_seen":
      return <TimeCell iso={finding.first_seen_at} />;
    case "cve":
      return finding.cve?.length ? (
        <span className="block truncate font-mono text-xs text-red-700 dark:text-red-400" title={finding.cve.join(", ")}>
          {finding.cve.join(", ")}
        </span>
      ) : (
        <EmptyMark />
      );
    case "tags":
      return <TagsCell tags={finding.tags ?? []} />;
    case "matched_at":
      return finding.matched_at ? (
        <span className="block truncate font-mono text-xs text-neutral-700 dark:text-neutral-200" title={finding.matched_at}>
          {finding.matched_at}
        </span>
      ) : (
        <EmptyMark />
      );
    default:
      return null;
  }
}

/** FindingsView is the deduplicated triage list: one row per tracked finding, with
 *  its Tenable-style effective state (New/Active/Resurfaced/Mitigated/…). */
export function FindingsView() {
  const navigate = useNavigate();

  // Filter + page live in the URL (browser state): navigating into a finding and
  // back, a refresh, or a shared link all restore them. The parent owns the
  // condition rows (so they survive the builder collapsing); the compiled query
  // is debounced (text inputs change per keystroke) before it drives the list +
  // export. With no `filter` param, the default "open findings" filter applies.
  const [searchParams, setSearchParams] = useSearchParams();
  const [rows, setRows] = useState<Row[]>(() => {
    const raw = searchParams.get("filter");
    if (raw) {
      try {
        return queryToRows(JSON.parse(raw));
      } catch {
        // fall through to the default on a malformed param
      }
    }
    return defaultRows();
  });
  const compiled = useMemo(() => rowsToQuery(rows), [rows]);
  const [filter, setFilter] = useState(compiled);
  const [filterOpen, setFilterOpen] = useState(false);
  const [offset, setOffset] = useState(() => Math.max(0, Number(searchParams.get("offset")) || 0));
  const [exporting, setExporting] = useState<ExportFormat | null>(null);
  const [exportNotice, setExportNotice] = useState<{ kind: "warning" | "error"; text: string } | null>(null);
  const [columnPrefs, setColumnPrefs] = useState<FindingsColumnPrefs>(() =>
    mergeFindingsColumns(readStoredFindingsColumns()),
  );
  const columnPrefsRef = useRef(columnPrefs);
  columnPrefsRef.current = columnPrefs;

  useEffect(() => {
    const t = setTimeout(() => setFilter(compiled), 300);
    return () => clearTimeout(t);
  }, [compiled]);

  // Mirror the applied filter + page into the URL (replace, so it doesn't spam
  // history). Navigating to a finding pushes a new entry, so Back restores this
  // one with its query intact. `sort` / `order` are preserved for #311 so this
  // rewrite does not drop a sort the column picker is responsible for.
  const searchParamsRef = useRef(searchParams);
  searchParamsRef.current = searchParams;
  useEffect(() => {
    const p = new URLSearchParams();
    p.set("filter", JSON.stringify(filter));
    if (offset > 0) p.set("offset", String(offset));
    const sort = searchParamsRef.current.get("sort");
    const order = searchParamsRef.current.get("order");
    if (sort) p.set("sort", sort);
    if (sort && order) p.set("order", order);
    setSearchParams(p, { replace: true });
  }, [filter, offset, setSearchParams]);

  // Another tab editing the same preference updates this table.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key !== FINDINGS_COLUMNS_KEY && e.key !== null) return;
      const next = mergeFindingsColumns(readStoredFindingsColumns());
      columnPrefsRef.current = next;
      setColumnPrefs(next);
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const sortParam = searchParams.get("sort");
  const sortColumn = columnIdForSort(sortParam);
  const columns = useMemo(
    () => visibleFindingsColumns(columnPrefs, sortParam),
    [columnPrefs, sortParam],
  );
  const tableMinWidth = findingsTableMinWidth(columns, columnPrefs);
  const endpointVisible = columns.some((col) => col.flexible);

  const replaceColumnPrefs = (next: FindingsColumnPrefs, options?: { dropWidths?: boolean }) => {
    columnPrefsRef.current = next;
    setColumnPrefs(next);
    writeStoredFindingsColumns(next, options);
  };

  const previewColumnWidth = (id: FindingsColumnId, width: number) => {
    const prev = columnPrefsRef.current;
    const next = { ...prev, [id]: { ...prev[id], width } };
    columnPrefsRef.current = next;
    setColumnPrefs(next);
  };

  const commitColumnWidth = (id: FindingsColumnId, width: number) => {
    const prev = columnPrefsRef.current;
    replaceColumnPrefs({ ...prev, [id]: { ...prev[id], width } });
  };

  const resetColumnWidth = (id: FindingsColumnId) => {
    const col = FINDINGS_COLUMNS.find((c) => c.id === id);
    if (col?.width == null) return;
    commitColumnWidth(id, col.width);
  };

  const clearSort = () => {
    const p = new URLSearchParams(searchParams);
    p.delete("sort");
    p.delete("order");
    setSearchParams(p, { replace: true });
  };

  const showColumn = (id: FindingsColumnId) => {
    const prev = columnPrefsRef.current;
    if (prev[id].visible) return;
    replaceColumnPrefs({ ...prev, [id]: { ...prev[id], visible: true } });
  };

  const hideColumn = (id: FindingsColumnId) => {
    const remaining = columns.filter((col) => col.id !== id);
    if (remaining.length === 0) return;
    if (id === sortColumn) clearSort();
    const prev = columnPrefsRef.current;
    if (prev[id].visible) replaceColumnPrefs({ ...prev, [id]: { ...prev[id], visible: false } });
  };

  // Targets power the Target condition's value picker (value = id, label = name).
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const targetOpts: Option[] = useMemo(
    () => (targets.data ?? []).map((t) => ({ value: t.id, label: t.name })),
    [targets.data],
  );
  const targetNames = useMemo(
    () => new Map((targets.data ?? []).map((t) => [t.id, t.name])),
    [targets.data],
  );

  const crumbs = useMemo(() => rowsToCrumbs(rows, targetOpts), [rows, targetOpts]);
  const activeCount = useMemo(() => countActiveConditions(rows), [rows]);

  // Changing the applied filter jumps back to page 1 — but not on first mount, so
  // an offset restored from the URL survives a back-navigation.
  const mounted = useRef(false);
  useEffect(() => {
    if (mounted.current) setOffset(0);
    else mounted.current = true;
  }, [filter]);

  const query = useQuery({
    queryKey: ["findings", filter, offset],
    queryFn: () => api.listFindings({ filter, limit: PAGE_SIZE, offset }),
    placeholderData: keepPreviousData,
  });

  const total = query.data?.total ?? 0;
  const items = query.data?.items ?? [];
  // Compare export rows only with a settled count for the same filter. During
  // debounce/refetch, keepPreviousData intentionally exposes the prior page;
  // using that total would create false incomplete-export warnings.
  const exportReady = query.data != null && !query.isFetching && !query.isPlaceholderData;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE_SIZE, total);

  useEffect(() => {
    setExportNotice(null);
  }, [filter, offset]);

  const download = async (format: ExportFormat) => {
    const expectedRows = total;
    setExporting(format);
    setExportNotice(null);
    try {
      const result = await api.fetchFindingsExport(format, { filter });
      const objectURL = URL.createObjectURL(result.blob);
      const a = document.createElement("a");
      a.href = objectURL;
      a.download = result.filename;
      a.rel = "noopener";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(objectURL), 0);

      // Raw exports report lifecycle rows without a live latest occurrence in a
      // separate header, so the UI can distinguish that omission from a count
      // mismatch caused by the intentional raw join.
      const rowCountMismatch =
        format !== "raw" && result.rowCount !== null && result.rowCount !== expectedRows;
      const rawMissingOccurrences = format === "raw" && result.missingOccurrences > 0;
      if (result.truncated || rowCountMismatch || rawMissingOccurrences) {
        const notices: string[] = [];
        if (result.truncated || rowCountMismatch) {
          const count = result.rowCount === null ? "an unknown number of" : `${result.rowCount} of ${expectedRows}`;
          notices.push(`The ${format.toUpperCase()} export may be incomplete: it contains ${count} findings.`);
        }
        if (rawMissingOccurrences) {
          notices.push(
            `The RAW export omits ${result.missingOccurrences} lifecycle findings whose latest occurrence is no longer stored.`,
          );
        }
        setExportNotice({
          kind: "warning",
          text: notices.join(" "),
        });
      }
    } catch (error) {
      setExportNotice({
        kind: "error",
        text: error instanceof Error ? error.message : "Unable to download findings export.",
      });
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="space-y-3">
      {/* Filter toggle + active-filter breadcrumb + export */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setFilterOpen((v) => !v)}
          aria-expanded={filterOpen}
          title={filterOpen ? "Hide filter" : "Show filter"}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium transition",
            filterOpen || activeCount > 0
              ? "border-indigo-400 bg-indigo-50 text-indigo-700 dark:border-indigo-600 dark:bg-indigo-950 dark:text-indigo-300"
              : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-800",
          )}
        >
          <Filter className="h-4 w-4" aria-hidden />
          Filter
          {activeCount > 0 && (
            <span className="rounded bg-indigo-600 px-1.5 text-xs font-semibold text-white">{activeCount}</span>
          )}
        </button>

        {/* Compact read-only summary of the active filter (visible when collapsed). */}
        {!filterOpen &&
          (crumbs.length > 0 ? (
            <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-sm text-neutral-500">
              {crumbs.map((b, i) => (
                <span key={i} className="inline-flex items-center gap-1.5">
                  {b.connector && (
                    <span className={b.connector === "or" ? "font-medium text-indigo-600 dark:text-indigo-400" : "text-neutral-400"}>
                      {b.connector}
                    </span>
                  )}
                  <span>
                    <span className="font-medium text-neutral-700 dark:text-neutral-200">{b.field}</span> {b.op}
                    {b.value && (
                      <span className="ml-1 rounded bg-indigo-50 px-1.5 py-0.5 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
                        {b.value}
                      </span>
                    )}
                  </span>
                </span>
              ))}
            </div>
          ) : (
            <span className="text-sm text-neutral-400">No filter — showing all findings</span>
          ))}

        <div className="ml-auto flex items-center gap-2">
          <DropdownMenu.Root>
            <DropdownMenu.Trigger asChild>
              <Button title="Choose columns">
                <Columns3 className="h-4 w-4" aria-hidden />
                Columns
              </Button>
            </DropdownMenu.Trigger>
            <DropdownMenu.Portal>
              <DropdownMenu.Content align="end" sideOffset={6} className={columnMenuCls}>
                {sortParam && !sortColumn && (
                  <DropdownMenu.Item
                    onSelect={clearSort}
                    className={cn(columnItemCls, "text-amber-700 dark:text-amber-400")}
                  >
                    Clear sort ({sortField(sortParam)})
                  </DropdownMenu.Item>
                )}
                {FINDINGS_COLUMNS.flatMap((col, index) => {
                  const shown = columns.some((c) => c.id === col.id);
                  const previous = FINDINGS_COLUMNS[index - 1];
                  const split = previous?.defaultVisible && !col.defaultVisible;
                  const item = (
                    <DropdownMenu.CheckboxItem
                      key={col.id}
                      checked={shown}
                      onSelect={(e) => e.preventDefault()}
                      onCheckedChange={(checked) => (checked ? showColumn(col.id) : hideColumn(col.id))}
                      className={columnItemCls}
                    >
                      <span className="flex h-4 w-4 items-center justify-center rounded border border-neutral-300 text-[10px] dark:border-neutral-600">
                        {shown ? "✓" : ""}
                      </span>
                      <span>{col.label}</span>
                      {sortColumn === col.id && (
                        <span className="ml-auto text-xs text-amber-700 dark:text-amber-400">sorted</span>
                      )}
                    </DropdownMenu.CheckboxItem>
                  );
                  if (!split) return [item];
                  return [
                    <DropdownMenu.Separator key={`${col.id}-split`} className="my-1 h-px bg-neutral-200 dark:bg-neutral-800" />,
                    item,
                  ];
                })}
                {FINDINGS_COLUMNS.some((col) => col.width != null && columnPrefs[col.id].width !== col.width) && (
                  <>
                    <DropdownMenu.Separator className="my-1 h-px bg-neutral-200 dark:bg-neutral-800" />
                    {FINDINGS_COLUMNS.filter((col) => col.width != null && columnPrefs[col.id].width !== col.width).map((col) => (
                      <DropdownMenu.Item
                        key={`reset-width-${col.id}`}
                        onSelect={() => resetColumnWidth(col.id)}
                        className={cn(columnItemCls, "text-neutral-500")}
                      >
                        Reset {col.label} width
                      </DropdownMenu.Item>
                    ))}
                  </>
                )}
                <DropdownMenu.Separator className="my-1 h-px bg-neutral-200 dark:bg-neutral-800" />
                <DropdownMenu.Item
                  onSelect={() => replaceColumnPrefs(mergeFindingsColumns(null), { dropWidths: true })}
                  className={cn(columnItemCls, "text-neutral-500")}
                >
                  Reset to default
                </DropdownMenu.Item>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
          <DropdownMenu.Root>
            <DropdownMenu.Trigger asChild>
              <Button
                disabled={exporting !== null || !exportReady}
                title={
                  exportReady
                    ? "Export the findings matching the current filter"
                    : "Wait for the current findings list to finish loading"
                }
              >
                {exporting ? "Exporting…" : "Export ▾"}
              </Button>
            </DropdownMenu.Trigger>
            <DropdownMenu.Portal>
              <DropdownMenu.Content
                align="end"
                sideOffset={6}
                className="min-w-40 rounded-md border border-neutral-200 bg-white p-1 shadow-lg dark:border-neutral-800 dark:bg-neutral-900"
              >
                <div className="px-2 py-1 text-xs text-neutral-500">
                  {total} finding{total === 1 ? "" : "s"} (current filter)
                </div>
                {EXPORT_FORMATS.map((f) => (
                  <DropdownMenu.Item
                    key={f.format}
                    onSelect={() => void download(f.format)}
                    className="cursor-pointer rounded px-2 py-1.5 text-sm outline-none hover:bg-neutral-100 dark:hover:bg-neutral-800"
                  >
                    {f.label}
                  </DropdownMenu.Item>
                ))}
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
        </div>
      </div>

      {exportNotice && (
        <div
          role={exportNotice.kind === "error" ? "alert" : "status"}
          className={cn(
            "rounded-md border px-3 py-2 text-sm",
            exportNotice.kind === "error"
              ? "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
              : "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300",
          )}
        >
          {exportNotice.text}
        </div>
      )}

      {filterOpen && (
        <Card className="p-3">
          <ConditionBuilder rows={rows} onChange={setRows} targetOptions={targetOpts} />
        </Card>
      )}

      <div className="px-1 text-sm text-neutral-500">
        {query.isLoading ? "…" : total === 0 ? "0 findings" : `${from}–${to} of ${total}`}
      </div>

      {query.isLoading ? (
        <Spinner label="Loading findings…" />
      ) : query.isError ? (
        <ErrorText error={query.error} />
      ) : (
        <>
          <Card>
            <div className="overflow-x-auto">
              <table
                className="table-fixed text-sm"
                style={{ minWidth: tableMinWidth, width: endpointVisible ? "100%" : tableMinWidth }}
              >
                <colgroup>
                  {columns.map((col) => (
                    <col key={col.id} style={col.flexible ? undefined : { width: columnPrefs[col.id].width }} />
                  ))}
                </colgroup>
                <thead>
                  <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                    {columns.map((col, index) => {
                      const resize = resizeHandleFor(columns, index, columnPrefs);
                      return (
                        <th key={col.id} scope="col" className="relative px-3 py-2 font-medium whitespace-nowrap">
                          <span className="block truncate">{col.label}</span>
                          {resize && (
                            <ColumnResizeHandle
                              target={resize}
                              onPreview={previewColumnWidth}
                              onCommit={commitColumnWidth}
                              onReset={resetColumnWidth}
                            />
                          )}
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody>
                  {items.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => navigate(`/findings/${f.id}`)}
                      className="cursor-pointer border-b border-neutral-100 hover:bg-neutral-50 last:border-0 dark:border-neutral-800/60 dark:hover:bg-neutral-800/40"
                    >
                      {columns.map((col) => (
                        <td key={col.id} className="max-w-0 overflow-hidden px-3 py-2">
                          <FindingCellSwitch id={col.id} finding={f} targetNames={targetNames} />
                        </td>
                      ))}
                    </tr>
                  ))}
                  {items.length === 0 && (
                    <tr>
                      <td colSpan={columns.length} className="px-3 py-8 text-center text-neutral-400">
                        No findings match.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>

          {total > PAGE_SIZE && (
            <div className="flex flex-wrap items-center justify-end gap-3 text-sm">
              <span className="text-neutral-500">
                Page {Math.floor(offset / PAGE_SIZE) + 1} of {Math.ceil(total / PAGE_SIZE)}
              </span>
              <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                ← Prev
              </Button>
              <Button disabled={to >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
                Next →
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
