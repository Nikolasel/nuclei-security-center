import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, scanRawUrl } from "../api";
import { ScanFindingsView } from "../components/ScanFindingsView";
import { Card, ErrorText, Spinner, StateBadge } from "../components/ui";

export function ScanDetailPage() {
  const { id = "" } = useParams();

  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
    refetchInterval: (q) => {
      const s = q.state.data?.state;
      return s === "queued" || s === "running" ? 2000 : false;
    },
  });

  const done = scan.data?.state === "complete" || scan.data?.state === "failed";

  return (
    <div className="space-y-5">
      <div>
        <Link to="/scans" className="text-sm text-indigo-600 hover:underline dark:text-indigo-400">
          ← Scans
        </Link>
        <h1 className="mt-1 flex items-center gap-3 text-xl font-semibold">
          <span className="font-mono text-base">{id.slice(0, 8)}</span>
          {scan.data && <StateBadge state={scan.data.state} />}
          {scan.data?.has_raw && (
            <a
              href={scanRawUrl(id)}
              className="ml-auto text-sm font-normal text-indigo-600 hover:underline dark:text-indigo-400"
            >
              Download raw output (JSONL)
            </a>
          )}
        </h1>
      </div>

      {scan.isLoading ? (
        <Spinner />
      ) : scan.isError ? (
        <ErrorText error={scan.error} />
      ) : (
        scan.data && (
          <Card className="p-4">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
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
