import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Button, Card, ErrorText, Input, SeverityBadge, Spinner } from "./ui";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 50;

export function FindingsView({ scanId }: { scanId?: string }) {
  const navigate = useNavigate();
  const [severity, setSeverity] = useState("");
  const [hostInput, setHostInput] = useState("");
  const [host, setHost] = useState("");
  const [offset, setOffset] = useState(0);

  // Debounce the host filter so we don't refetch on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => setHost(hostInput.trim()), 300);
    return () => clearTimeout(t);
  }, [hostInput]);

  // Any filter change resets to the first page.
  useEffect(() => {
    setOffset(0);
  }, [severity, host, scanId]);

  const q = useQuery({
    queryKey: ["findings", { scanId, severity, host, offset }],
    queryFn: () => api.listFindings({ scanId, severity, host, limit: PAGE_SIZE, offset }),
    placeholderData: keepPreviousData,
  });

  const total = q.data?.total ?? 0;
  const items = q.data?.items ?? [];
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE_SIZE, total);

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
          <Input
            value={hostInput}
            onChange={(e) => setHostInput(e.target.value)}
            placeholder="filter host…"
            className="w-48"
          />
        </label>
        <span className="pb-1.5 text-sm text-neutral-500">
          {q.isLoading ? "…" : total === 0 ? "0 findings" : `${from}–${to} of ${total}`}
        </span>
      </div>

      {q.isLoading ? (
        <Spinner label="Loading findings…" />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : (
        <>
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
                  {items.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => navigate(`/findings/${f.id}`)}
                      className="cursor-pointer border-b border-neutral-100 last:border-0 hover:bg-neutral-50 dark:border-neutral-800/60 dark:hover:bg-neutral-800/40"
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
                  {items.length === 0 && (
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
