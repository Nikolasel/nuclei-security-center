import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { resultIdentityLine, resultIdentityTitle } from "./findingsColumns";
import { Card, cn, ErrorText, focusRing, Input, Muted, OffsetPager, SeverityBadge, Spinner, Table, TableEmpty, Td, Th, THead, TRow } from "./ui";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 50;

const sevChip: Record<string, string> = {
  critical: "bg-red-600 text-white border-red-600",
  high: "bg-orange-500 text-white border-orange-500",
  medium: "bg-amber-500 text-white border-amber-500",
  low: "bg-yellow-500 text-white border-yellow-500",
  info: "bg-sky-500 text-white border-sky-500",
};

/** ScanFindingsView lists the immutable occurrences a single scan observed. Rows
 *  open that exact raw occurrence, independent of the global lifecycle view. */
export function ScanFindingsView({ scanId }: { scanId: string }) {
  const navigate = useNavigate();

  const [q, setQ] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const [applied, setApplied] = useState("");
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => setApplied(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);

  const sevKey = severities.join(",");
  useEffect(() => {
    setOffset(0);
  }, [applied, sevKey, scanId]);

  const query = useQuery({
    queryKey: ["scan-findings", scanId, { applied, sevKey, offset }],
    queryFn: () => api.listScanFindings(scanId, { q: applied, severities, limit: PAGE_SIZE, offset }),
    placeholderData: keepPreviousData,
  });

  const total = query.data?.total ?? 0;
  const items = query.data?.items ?? [];

  const toggleSeverity = (s: string) =>
    setSeverities((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  return (
    <div className="space-y-3">
      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">Search (name or template)</span>
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. ssl, log4j…" className="w-56 shrink-0" />
          </label>
          <div className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">Severity</span>
            <div className="flex flex-wrap gap-1">
              {SEVERITIES.map((s) => {
                const active = severities.includes(s);
                return (
                  <button
                    key={s}
                    type="button"
                    aria-pressed={active}
                    onClick={() => toggleSeverity(s)}
                    className={cn(
                      "h-9 rounded-md border px-2.5 text-xs font-medium uppercase tracking-wide transition",
                      focusRing,
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
        </div>
      </Card>

      <div className="px-1 text-sm text-neutral-500">
        {query.isLoading ? "…" : total === 0 ? "0 findings" : `${total} finding${total === 1 ? "" : "s"} in this scan`}
      </div>

      {query.isLoading ? (
        <Spinner label="Loading findings…" />
      ) : query.isError ? (
        <ErrorText error={query.error} />
      ) : (
        <>
          <Card>
            <Table>
              <THead>
                <Th>Severity</Th>
                <Th>Name</Th>
                <Th>CVE</Th>
                <Th>Template</Th>
                <Th>Host</Th>
                <Th>Matched</Th>
              </THead>
              <tbody>
                {items.map((f) => (
                  <TRow key={f.id} onClick={() => navigate(`/occurrences/${f.id}`)}>
                    <Td>
                      <SeverityBadge severity={f.severity} />
                    </Td>
                    <Td>
                      <div>{f.name || <Muted />}</div>
                      {(f.matcher_name || f.extractor_name || f.extracted_results?.length) ? (
                        <div className="truncate font-mono text-[11px] text-neutral-500" title={resultIdentityTitle(f)}>
                          {resultIdentityLine(f)}
                        </div>
                      ) : null}
                    </Td>
                    <Td>
                      {f.cve?.length ? (
                        <span className="font-mono text-xs text-red-700 dark:text-red-400">{f.cve.join(", ")}</span>
                      ) : (
                        <Muted />
                      )}
                    </Td>
                    <Td className="font-mono text-xs">{f.template_id}</Td>
                    <Td>{f.host}</Td>
                    <Td className="font-mono text-xs text-neutral-500">{f.matched_at}</Td>
                  </TRow>
                ))}
                {items.length === 0 && <TableEmpty colSpan={6}>No findings match.</TableEmpty>}
              </tbody>
            </Table>
          </Card>

          <OffsetPager offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
        </>
      )}
    </div>
  );
}
