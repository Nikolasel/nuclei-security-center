import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, FINDING_STATUSES, STATUS_LABELS, type FindingsView as View, type FindingStatus } from "../api";
import { Button, Card, cn, ErrorText, Input, Pill, Select, SeverityBadge, Spinner, StatusBadge } from "./ui";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 50;

const VIEWS: { key: View; label: string }[] = [
  { key: "all", label: "All" },
  { key: "open", label: "Open" },
  { key: "new", label: "New" },
  { key: "resolved", label: "Resolved" },
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

/** FindingsView is the deduplicated triage list: one row per tracked finding,
 *  with lifecycle status and new/resolved facets. */
export function FindingsView() {
  const navigate = useNavigate();

  const [q, setQ] = useState("");
  const [host, setHost] = useState("");
  const [cve, setCve] = useState("");
  const [tag, setTag] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const [status, setStatus] = useState<FindingStatus | "">("");
  const [view, setView] = useState<View>("all");
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
  }, [applied, sevKey, status, view]);

  const query = useQuery({
    queryKey: ["findings", { applied, sevKey, status, view, offset }],
    queryFn: () =>
      api.listFindings({
        q: applied.q,
        host: applied.host,
        cve: applied.cve,
        tag: applied.tag,
        severities,
        status: status || undefined,
        view,
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
      (status ? 1 : 0) +
      [applied.q, applied.host, applied.cve, applied.tag].filter(Boolean).length,
    [severities, status, applied],
  );

  const toggleSeverity = (s: string) =>
    setSeverities((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  const clearAll = () => {
    setQ("");
    setHost("");
    setCve("");
    setTag("");
    setSeverities([]);
    setStatus("");
  };

  return (
    <div className="space-y-3">
      {/* View tabs */}
      <div className="flex gap-1">
        {VIEWS.map((v) => (
          <button
            key={v.key}
            onClick={() => setView(v.key)}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm font-medium transition",
              view === v.key
                ? "bg-indigo-600 text-white"
                : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800",
            )}
          >
            {v.label}
          </button>
        ))}
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
            <span className="block text-xs font-medium text-neutral-500">Status</span>
            <Select value={status} onChange={(e) => setStatus(e.target.value as FindingStatus | "")}>
              <option value="">Any</option>
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABELS[s]}
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
                    <th className="px-3 py-2 font-medium">Status</th>
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
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span>{f.name || <span className="text-neutral-400">—</span>}</span>
                          {f.new && <Pill tone="new">New</Pill>}
                          {f.resolved && <Pill tone="resolved">Resolved</Pill>}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <StatusBadge status={f.status} />
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
