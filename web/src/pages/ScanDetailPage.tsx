import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, scanBundleExportUrl, scanLogUrl, scanRawUrl, type EndpointCoverage } from "../api";
import { hasRole, useMe } from "../auth";
import { ScanFindingsView } from "../components/ScanFindingsView";
import { Button, Card, ErrorText, ProgressBar, Spinner, StateBadge } from "../components/ui";
import { formatDuration, scanEtaSeconds } from "../util";

export function ScanDetailPage() {
  const { id = "" } = useParams();
  const me = useMe();
  const canCancel = hasRole(me.data ?? undefined, "operator");
  const qc = useQueryClient();

  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
    refetchInterval: (q) => {
      const s = q.state.data?.state;
      return s === "queued" || s === "running" ? 2000 : false;
    },
  });

  const cancel = useMutation({
    mutationFn: () => api.cancelScan(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scan", id] });
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const state = scan.data?.state;
  const active = state === "queued" || state === "running";
  // Terminal states: findings (if any were ingested) are shown; a cancelled scan
  // typically has none since ingest only runs on successful completion.
  const done = state === "complete" || state === "failed" || state === "cancelled";

  return (
    <div className="space-y-5">
      <div>
        <Link to="/scans" className="text-sm text-indigo-600 hover:underline dark:text-indigo-400">
          ← Scans
        </Link>
        <h1 className="mt-1 flex items-center gap-3 text-xl font-semibold">
          <span className="font-mono text-base">{id.slice(0, 8)}</span>
          {scan.data && <StateBadge state={scan.data.state} />}
          <span className="ml-auto flex items-center gap-3">
            {canCancel && active && (
              <Button
                variant="ghost"
                disabled={cancel.isPending}
                onClick={() => {
                  if (confirm(`Stop scan ${id.slice(0, 8)}?`)) cancel.mutate();
                }}
              >
                Stop scan
              </Button>
            )}
            {scan.data?.has_raw && (
              <a
                href={scanRawUrl(id)}
                className="text-sm font-normal text-indigo-600 hover:underline dark:text-indigo-400"
              >
                Download raw output (JSONL)
              </a>
            )}
            {scan.data?.has_log && (
              <a
                href={scanLogUrl(id)}
                className="text-sm font-normal text-indigo-600 hover:underline dark:text-indigo-400"
              >
                Download log
              </a>
            )}
            <a
              href={scanBundleExportUrl(id, "zip")}
              className="text-sm font-normal text-indigo-600 hover:underline dark:text-indigo-400"
              title="Complete scan bundle: scan record, findings, raw output and finding lifecycle (#136)"
            >
              Download bundle (zip)
            </a>
            <a
              href={scanBundleExportUrl(id)}
              className="text-sm font-normal text-indigo-600 hover:underline dark:text-indigo-400"
              title="Same bundle as readable JSON (#136)"
            >
              Download bundle (JSON)
            </a>
          </span>
        </h1>
      </div>

      {cancel.isError && <ErrorText error={cancel.error} />}

      {scan.isLoading ? (
        <Spinner />
      ) : scan.isError ? (
        <ErrorText error={scan.error} />
      ) : (
        scan.data && (
          <Card className="p-4">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
              <div>
                <dt className="text-xs text-neutral-500">Target</dt>
                <dd>
                  {scan.data.target_name ? (
                    <>
                      {scan.data.target_id ? (
                        <Link
                          to="/targets"
                          className="text-indigo-600 hover:underline dark:text-indigo-400"
                        >
                          {scan.data.target_name}
                        </Link>
                      ) : (
                        scan.data.target_name
                      )}
                      {scan.data.target_host_count ? (
                        <span className="text-neutral-400">
                          {" "}
                          ({scan.data.target_host_count} host
                          {scan.data.target_host_count === 1 ? "" : "s"})
                        </span>
                      ) : null}
                    </>
                  ) : (
                    <span className="text-neutral-400">ad-hoc</span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-neutral-500">Scanner node</dt>
                <dd>
                  {scan.data.node_name ? (
                    scan.data.node_id ? (
                      <Link
                        to="/nodes"
                        className="text-indigo-600 hover:underline dark:text-indigo-400"
                      >
                        {scan.data.node_name}
                      </Link>
                    ) : (
                      scan.data.node_name
                    )
                  ) : (
                    <span className="text-neutral-400">—</span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-neutral-500">Scan policy</dt>
                <dd>
                  {scan.data.scan_policy_name ? (
                    scan.data.scan_policy_id ? (
                      <Link
                        to="/scan-policies"
                        className="text-indigo-600 hover:underline dark:text-indigo-400"
                      >
                        {scan.data.scan_policy_name}
                      </Link>
                    ) : (
                      scan.data.scan_policy_name
                    )
                  ) : (
                    <span className="text-neutral-400">Default</span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-neutral-500">Template set</dt>
                <dd>
                  {scan.data.template_set_name ? (
                    scan.data.template_set_id ? (
                      <Link
                        to="/template-sets"
                        className="text-indigo-600 hover:underline dark:text-indigo-400"
                      >
                        {scan.data.template_set_name}
                      </Link>
                    ) : (
                      scan.data.template_set_name
                    )
                  ) : (
                    <span className="text-neutral-400">—</span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-neutral-500">Created</dt>
                <dd>{new Date(scan.data.created_at).toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-xs text-neutral-500">Finished</dt>
                <dd>{scan.data.finished_at ? new Date(scan.data.finished_at).toLocaleString() : "—"}</dd>
              </div>
              <div>
                <dt className="text-xs text-neutral-500">Nuclei</dt>
                <dd className="font-mono text-xs">{scan.data.nuclei_version || "—"}</dd>
              </div>
            </dl>
            {/* Discovery phase (naabu, #86): no clean percentage, so an animated
                bar with the live per-host tally. The host count is naabu's
                host-discovery probe result ("responding", not "alive"): on a NAT'd
                dev network — Docker Desktop — every address answers, so the
                authoritative narrowed set is the "Discovered endpoints" list below,
                sourced from naabu's JSON rather than this live tally. */}
            {scan.data.state === "running" && scan.data.progress?.phase === "discovering" && (
              <div className="mt-4">
                <ProgressBar percent={0} indeterminate label="discovering…" />
                <p className="mt-1 text-xs text-neutral-500">
                  Discovering live hosts &amp; ports (naabu) · {scan.data.progress.disc_hosts ?? 0}{" "}
                  {(scan.data.progress.disc_hosts ?? 0) === 1 ? "host" : "hosts"} responding ·{" "}
                  {scan.data.progress.disc_ports ?? 0}{" "}
                  {(scan.data.progress.disc_ports ?? 0) === 1 ? "open port" : "open ports"} so far
                </p>
              </div>
            )}
            {/* Scanning phase (Nuclei): request-based percentage, stats shown
                per-target (#86) rather than as one overall counter. */}
            {scan.data.state === "running" &&
              scan.data.progress &&
              scan.data.progress.phase !== "discovering" && (
                <div className="mt-4">
                  <ProgressBar percent={scan.data.progress.percent} />
                  <p className="mt-1 text-xs text-neutral-500">
                    {(() => {
                      const p = scan.data.progress;
                      const done = p.requests ?? 0;
                      const total = p.total ?? 0;
                      // Nuclei reports only OVERALL request counts, not per-target
                      // progress — it interleaves templates across all targets rather
                      // than finishing one before the next. So show the real overall
                      // numbers, and translate the completion fraction into an
                      // ESTIMATE of targets done (~frac × count) rather than faking a
                      // per-target request figure by dividing the total. When discovery
                      // ran, the target count is the authoritative discovered-endpoint
                      // count (stable, and matches the "N ports on M hosts" line below);
                      // Nuclei's own "hosts" stat counts distinct hosts and fluctuates.
                      // Without discovery, fall back to that host count.
                      const discovered = scan.data.discovered_targets?.length ?? 0;
                      const count = discovered > 0 ? discovered : (p.hosts ?? 0);
                      const unit = discovered > 0 ? "endpoint" : "host";
                      const frac = total > 0 ? done / total : (p.percent ?? 0) / 100;
                      const estDone = Math.min(count, Math.round(frac * count));
                      const summary =
                        count > 0
                          ? `${done.toLocaleString()} / ${total.toLocaleString()} requests · ~${estDone} of ${count} ${unit}${count === 1 ? "" : "s"} scanned`
                          : `${done.toLocaleString()} / ${total.toLocaleString()} requests`;
                      const elapsed = (Date.now() - new Date(scan.data.created_at).getTime()) / 1000;
                      const eta = scanEtaSeconds(p, elapsed);
                      return (
                        <>
                          {summary}
                          {p.rps ? ` · ${p.rps} rps` : ""} ·{" "}
                          {eta != null ? `${formatDuration(eta)} remaining` : "estimating…"}
                        </>
                      );
                    })()}
                  </p>
                </div>
              )}
            {scan.data.state === "running" && !scan.data.progress && (
              <p className="mt-4 text-xs text-neutral-400">Waiting for progress from the scanner…</p>
            )}
            {scan.data.error && (
              <p className="mt-3 rounded bg-red-50 px-3 py-2 text-sm whitespace-pre-wrap break-words text-red-700 dark:bg-red-950 dark:text-red-300">
                {scan.data.error}
              </p>
            )}
            {scan.data.skipped_finding_count > 0 && (
              <p className="mt-3 rounded bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950 dark:text-amber-300">
                {scan.data.skipped_finding_count.toLocaleString()}{" "}malformed finding{" "}
                {scan.data.skipped_finding_count === 1 ? "record was" : "records were"} skipped during ingest;
                indexed results are partial; absent findings cannot be auto-mitigated from this scan.
                Operational ingest failures remain scan-fatal.
              </p>
            )}
            {scan.data.discovered_targets && scan.data.discovered_targets.length > 0 && (
              <DiscoveredEndpoints targets={scan.data.discovered_targets} />
            )}
            {scan.data.state !== "running" && (
              <CoveredEndpoints
                endpoints={scan.data.covered_endpoints}
                warning={scan.data.coverage_warning}
              />
            )}
          </Card>
        )
      )}

      {!done ? (
        <p className="text-sm text-neutral-500">Findings appear here once the scan finishes.</p>
      ) : (
        <ScanFindingsView scanId={id} />
      )}
    </div>
  );
}

// CoveredEndpoints is the durable lifecycle evidence introduced by #91. Keep
// "unknown" distinct from a known empty trace: old scans must fail closed, while
// a completed scan that reached nothing has an explicit, explainable result.
function CoveredEndpoints({
  endpoints,
  warning,
}: {
  endpoints?: EndpointCoverage[] | null;
  warning?: string;
}) {
  if (endpoints == null) {
    return (
      <div className="mt-4 rounded bg-amber-50 px-3 py-2 text-xs text-amber-700 dark:bg-amber-950 dark:text-amber-300">
        <p>Endpoint coverage unavailable · this scan cannot mark absent findings as mitigated</p>
        {warning && <p className="mt-1 break-words">{warning}</p>}
      </div>
    );
  }
  const visibleEndpoints = endpoints.slice(0, 500);
  return (
    <div className="mt-4">
      <p className="text-xs font-medium text-neutral-500">
        Template/endpoint checks completed · {endpoints.length.toLocaleString()}{" "}
        {endpoints.length === 1 ? "pair" : "pairs"}
      </p>
      {warning && (
        <p className="mt-1 rounded bg-amber-50 px-2 py-1 text-xs break-words text-amber-700 dark:bg-amber-950 dark:text-amber-300">
          {warning}
        </p>
      )}
      {endpoints.length === 0 ? (
        <p className="mt-1 text-xs text-neutral-400">
          No template/endpoint pair completed a successful request.
        </p>
      ) : (
        <div className="mt-2 flex max-h-40 flex-wrap gap-1 overflow-y-auto">
          {visibleEndpoints.map((pair) => (
            <span
              key={`${pair.template_id}\u001f${pair.endpoint}`}
              className="rounded bg-neutral-100 px-2 py-1 font-mono text-xs text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300"
            >
              {pair.template_id} · {pair.endpoint}
            </span>
          ))}
          {endpoints.length > visibleEndpoints.length && (
            <span className="px-2 py-1 text-xs text-neutral-400">
              +{(endpoints.length - visibleEndpoints.length).toLocaleString()} more
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// DiscoveredEndpoints lists the host:port pairs the naabu pre-pass narrowed the
// target to (#86), grouped by host, so it's clear which endpoints Nuclei actually
// scanned. Shown whenever discovery ran (live during the scanning phase, and
// persisted after completion).
function DiscoveredEndpoints({ targets }: { targets: string[] }) {
  const groups = groupEndpoints(targets);
  const portCount = targets.length;
  return (
    <div className="mt-4">
      <p className="text-xs font-medium text-neutral-500">
        Discovered endpoints (naabu) · {portCount} {portCount === 1 ? "port" : "ports"} on {groups.length}{" "}
        {groups.length === 1 ? "host" : "hosts"}
      </p>
      <div className="mt-2 max-h-60 space-y-1 overflow-y-auto">
        {groups.map((g) => (
          <div key={g.host} className="flex flex-wrap items-baseline gap-x-2 text-xs">
            <span className="font-mono text-neutral-700 dark:text-neutral-300">{g.host}</span>
            <span className="font-mono text-neutral-500">{g.ports.join(", ")}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// groupEndpoints turns a flat host:port list into per-host port groups. It splits
// on the LAST colon so IPv6 literals ("[::1]:80") keep their bracketed host.
function groupEndpoints(targets: string[]): { host: string; ports: string[] }[] {
  const map = new Map<string, string[]>();
  for (const t of targets) {
    const idx = t.lastIndexOf(":");
    const host = idx > 0 ? t.slice(0, idx) : t;
    const port = idx > 0 ? t.slice(idx + 1) : "";
    const ports = map.get(host) ?? [];
    if (port) ports.push(port);
    map.set(host, ports);
  }
  return [...map.entries()].map(([host, ports]) => ({ host, ports }));
}
