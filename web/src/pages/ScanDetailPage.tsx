import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, scanLogUrl, scanRawUrl } from "../api";
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
              <div>
                <dt className="text-xs text-neutral-500">Templates</dt>
                <dd className="font-mono text-xs">{scan.data.templates_commit || "—"}</dd>
              </div>
            </dl>
            {scan.data.state === "running" && scan.data.progress && (
              <div className="mt-4">
                <ProgressBar percent={scan.data.progress.percent} />
                <p className="mt-1 text-xs text-neutral-500">
                  {scan.data.progress.requests?.toLocaleString() ?? 0} /{" "}
                  {scan.data.progress.total?.toLocaleString() ?? 0} requests
                  {scan.data.progress.hosts ? ` · ${scan.data.progress.hosts} hosts` : ""}
                  {scan.data.progress.rps ? ` · ${scan.data.progress.rps} rps` : ""}
                  {" · "}
                  {(() => {
                    // ETA is an estimate off Nuclei's own request-based progress,
                    // not a countdown clock; show "estimating…" until it settles.
                    const elapsed = (Date.now() - new Date(scan.data.created_at).getTime()) / 1000;
                    const eta = scanEtaSeconds(scan.data.progress, elapsed);
                    return eta != null ? `${formatDuration(eta)} remaining` : "estimating…";
                  })()}
                </p>
              </div>
            )}
            {scan.data.state === "running" && !scan.data.progress && (
              <p className="mt-4 text-xs text-neutral-400">Waiting for progress from the scanner…</p>
            )}
            {scan.data.error && (
              <p className="mt-3 rounded bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950 dark:text-red-300">
                {scan.data.error}
              </p>
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
