import { useMemo, useState } from "react";
import type { Finding } from "../api";
import { Card, Input, SeverityBadge } from "./ui";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function FindingsView({ findings }: { findings: Finding[] }) {
  const [severity, setSeverity] = useState("");
  const [host, setHost] = useState("");
  const [template, setTemplate] = useState("");

  const filtered = useMemo(() => {
    const h = host.trim().toLowerCase();
    const t = template.trim().toLowerCase();
    return findings
      .filter((f) => (severity ? f.severity.toLowerCase() === severity : true))
      .filter((f) => (h ? f.host.toLowerCase().includes(h) : true))
      .filter((f) =>
        t ? f.template_id.toLowerCase().includes(t) || f.name.toLowerCase().includes(t) : true,
      )
      .sort((a, b) => (rank[b.severity.toLowerCase()] ?? 0) - (rank[a.severity.toLowerCase()] ?? 0));
  }, [findings, severity, host, template]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1">
          <span className="block text-xs font-medium text-neutral-500">Severity</span>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-md border border-neutral-300 bg-white px-2 py-1.5 text-sm dark:border-neutral-700 dark:bg-neutral-800"
          >
            <option value="">All</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1">
          <span className="block text-xs font-medium text-neutral-500">Host</span>
          <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="filter host…" className="w-48" />
        </label>
        <label className="space-y-1">
          <span className="block text-xs font-medium text-neutral-500">Template / name</span>
          <Input
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            placeholder="filter template…"
            className="w-56"
          />
        </label>
        <span className="pb-1.5 text-sm text-neutral-500">
          {filtered.length} of {findings.length}
        </span>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium">Template</th>
                <th className="px-3 py-2 font-medium">Host</th>
                <th className="px-3 py-2 font-medium">Matched</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr
                  key={f.id}
                  className="border-b border-neutral-100 last:border-0 hover:bg-neutral-50 dark:border-neutral-800/60 dark:hover:bg-neutral-800/40"
                >
                  <td className="px-3 py-2">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-3 py-2">{f.name || <span className="text-neutral-400">—</span>}</td>
                  <td className="px-3 py-2 font-mono text-xs">{f.template_id}</td>
                  <td className="px-3 py-2">{f.host}</td>
                  <td className="px-3 py-2 font-mono text-xs text-neutral-500">{f.matched_at}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-neutral-400">
                    No findings match.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
