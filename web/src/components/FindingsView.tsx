import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  api,
  DISPOSITION_LABELS,
  DISPOSITIONS,
  EFFECTIVE_STATES,
  findingsExportUrl,
  STATE_LABELS,
  type Disposition,
  type EffectiveState,
  type ExportFormat,
} from "../api";
import { Button, Card, cn, ErrorText, FindingStateBadge, Input, Pill, Select, SeverityBadge, Spinner } from "./ui";

const EXPORT_FORMATS: { format: ExportFormat; label: string }[] = [
  { format: "json", label: "JSON" },
  { format: "csv", label: "CSV" },
  { format: "sarif", label: "SARIF" },
  { format: "raw", label: "Raw (JSONL)" },
];

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 50;

// Tab cuts over the derived effective state. "" = All.
const TABS: { key: EffectiveState | ""; label: string }[] = [
  { key: "", label: "All" },
  ...EFFECTIVE_STATES.map((s) => ({ key: s, label: STATE_LABELS[s] })),
];

const sevChip: Record<string, string> = {
  critical: "bg-red-600 text-white border-red-600",
  high: "bg-orange-500 text-white border-orange-500",
  medium: "bg-amber-500 text-white border-amber-500",
  low: "bg-yellow-500 text-white border-yellow-500",
  info: "bg-sky-500 text-white border-sky-500",
};

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

  const [q, setQ] = useState("");
  const [host, setHost] = useState("");
  const [cve, setCve] = useState("");
  const [tag, setTag] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const [disposition, setDisposition] = useState<Disposition | "">("");
  const [state, setState] = useState<EffectiveState | "">("");
  const [applied, setApplied] = useState({ q: "", host: "", cve: "", tag: "" });
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const t = setTimeout(
      () => setApplied({ q: q.trim(), host: host.trim(), cve: cve.trim(), tag: tag.trim() }),
      300,
    );
    return () => clearTimeout(t);
  }, [q, host, cve, tag]);

  const sevKey = severities.join(",");
  useEffect(() => {
    setOffset(0);
  }, [applied, sevKey, disposition, state]);

  const query = useQuery({
    queryKey: ["findings", { applied, sevKey, disposition, state, offset }],
    queryFn: () =>
      api.listFindings({
        q: applied.q,
        host: applied.host,
        cve: applied.cve,
        tag: applied.tag,
        severities,
        disposition: disposition || undefined,
        state: state || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    placeholderData: keepPreviousData,
  });

  const total = query.data?.total ?? 0;
  const items = query.data?.items ?? [];
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE_SIZE, total);

  const activeCount = useMemo(
    () =>
      severities.length +
      (disposition ? 1 : 0) +
      [applied.q, applied.host, applied.cve, applied.tag].filter(Boolean).length,
    [severities, disposition, applied],
  );

  // Export URL uses the same filters the list is currently showing.
  const exportQuery = {
    q: applied.q,
    host: applied.host,
    cve: applied.cve,
    tag: applied.tag,
    severities,
    disposition: disposition || undefined,
    state: state || undefined,
  };
  const download = (format: ExportFormat) => {
    const a = document.createElement("a");
    a.href = findingsExportUrl(format, exportQuery);
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const toggleSeverity = (s: string) =>
    setSeverities((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  const clearAll = () => {
    setQ("");
    setHost("");
    setCve("");
    setTag("");
    setSeverities([]);
    setDisposition("");
  };

  return (
    <div className="space-y-3">
      {/* Effective-state tabs + export */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap gap-1">
          {TABS.map((t) => (
            <button
              key={t.key || "all"}
              onClick={() => setState(t.key)}
              className={cn(
                "rounded-md px-3 py-1.5 text-sm font-medium transition",
                state === t.key
                  ? "bg-indigo-600 text-white"
                  : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800",
              )}
            >
              {t.label}
            </button>
          ))}
        </div>

        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <Button className="ml-auto" title="Export the findings matching the current filters">
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
                {total} finding{total === 1 ? "" : "s"} (current filters)
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

      <Card className="p-3">
        <div className="flex flex-wrap items-end gap-3">
          <label className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">Search (name or template)</span>
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. ssl, log4j…" className="w-56" />
          </label>
          <label className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">CVE</span>
            <Input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2021-…" className="w-40" />
          </label>
          <label className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">Host</span>
            <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="filter host…" className="w-40" />
          </label>
          <label className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">Tag</span>
            <Input value={tag} onChange={(e) => setTag(e.target.value)} placeholder="exact tag…" className="w-36" />
          </label>
          <label className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">Disposition</span>
            <Select value={disposition} onChange={(e) => setDisposition(e.target.value as Disposition | "")}>
              <option value="">Any</option>
              {DISPOSITIONS.map((d) => (
                <option key={d} value={d}>
                  {DISPOSITION_LABELS[d]}
                </option>
              ))}
            </Select>
          </label>
          <div className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">Severity</span>
            <div className="flex flex-wrap gap-1">
              {SEVERITIES.map((s) => {
                const active = severities.includes(s);
                return (
                  <button
                    key={s}
                    onClick={() => toggleSeverity(s)}
                    className={cn(
                      "rounded border px-2 py-1 text-xs font-medium uppercase tracking-wide transition",
                      active
                        ? sevChip[s]
                        : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-800",
                    )}
                  >
                    {s}
                  </button>
                );
              })}
            </div>
          </div>
          {activeCount > 0 && (
            <Button variant="ghost" onClick={clearAll} className="text-sm">
              Clear ({activeCount})
            </Button>
          )}
        </div>
      </Card>

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
