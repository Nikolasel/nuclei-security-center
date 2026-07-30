import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Filter } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, findingsExportUrl, type ExportFormat } from "../api";
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

  useEffect(() => {
    const t = setTimeout(() => setFilter(compiled), 300);
    return () => clearTimeout(t);
  }, [compiled]);

  // Mirror the applied filter + page into the URL (replace, so it doesn't spam
  // history). Navigating to a finding pushes a new entry, so Back restores this
  // one with its query intact.
  useEffect(() => {
    const p = new URLSearchParams();
    p.set("filter", JSON.stringify(filter));
    if (offset > 0) p.set("offset", String(offset));
    setSearchParams(p, { replace: true });
  }, [filter, offset, setSearchParams]);

  // Targets power the Target condition's value picker (value = id, label = name).
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const targetOpts: Option[] = useMemo(
    () => (targets.data ?? []).map((t) => ({ value: t.id, label: t.name })),
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
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE_SIZE, total);

  const download = (format: ExportFormat) => {
    const a = document.createElement("a");
    a.href = findingsExportUrl(format, { filter });
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
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

        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <Button className="ml-auto" title="Export the findings matching the current filter">
              Export ▾
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
                  onSelect={() => download(f.format)}
                  className="cursor-pointer rounded px-2 py-1.5 text-sm outline-none hover:bg-neutral-100 dark:hover:bg-neutral-800"
                >
                  {f.label}
                </DropdownMenu.Item>
              ))}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>

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
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                    <th className="px-3 py-2 font-medium">Severity</th>
                    <th className="px-3 py-2 font-medium">Name</th>
                    <th className="px-3 py-2 font-medium">State</th>
                    <th className="px-3 py-2 font-medium">CVE</th>
                    <th className="px-3 py-2 font-medium">Host</th>
                    <th className="px-3 py-2 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => navigate(`/findings/${f.id}`)}
                      className="cursor-pointer border-b border-neutral-100 last:border-0 hover:bg-neutral-50 dark:border-neutral-800/60 dark:hover:bg-neutral-800/40"
                    >
                      <td className="px-3 py-2">
                        <SeverityBadge severity={f.effective_severity} recast={!!f.recast_severity} />
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span>{f.name || <span className="text-neutral-400">—</span>}</span>
                          {f.times_mitigated > 0 && (
                            <Pill tone="warn">
                              <span title="Times gone then re-observed">↻ {f.times_mitigated}</span>
                            </Pill>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <FindingStateBadge state={f.effective_state} />
                        {!f.auto_mitigation_eligible && (
                          <span
                            className="ml-2 text-xs text-amber-600 dark:text-amber-400"
                            title="No network host:port; scan absence cannot automatically mark this finding mitigated"
                          >
                            auto-mitigation unavailable
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        {f.cve?.length ? (
                          <span className="font-mono text-xs text-red-700 dark:text-red-400">{f.cve.join(", ")}</span>
                        ) : (
                          <span className="text-neutral-300 dark:text-neutral-600">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2">{f.host}</td>
                      <td className="px-3 py-2 text-xs text-neutral-500" title={new Date(f.last_seen_at).toLocaleString()}>
                        {relTime(f.last_seen_at)}
                      </td>
                    </tr>
                  ))}
                  {items.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-3 py-8 text-center text-neutral-400">
                        No findings match.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>

          {total > PAGE_SIZE && (
            <div className="flex items-center justify-end gap-3 text-sm">
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
