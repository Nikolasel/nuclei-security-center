import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Modal, Spinner, StateBadge } from "../components/ui";

function RunScanModal({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const templateSets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const [targetId, setTargetId] = useState("");
  const [templateSetId, setTemplateSetId] = useState("");

  const run = useMutation({
    mutationFn: () =>
      api.createScan({ target_id: targetId, template_set_id: templateSetId || undefined }),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["scans"] });
      onClose();
      navigate(`/scans/${res.scan_id}`);
    },
  });

  const selectCls =
    "w-full rounded-md border border-neutral-300 bg-white px-3 py-1.5 text-sm dark:border-neutral-700 dark:bg-neutral-800";

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title="Run scan">
      <div className="space-y-4">
        <Field label="Target (scope allowlist)">
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)} className={selectCls}>
            <option value="">Select a target…</option>
            {(targets.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.hosts.length} host{t.hosts.length === 1 ? "" : "s"})
              </option>
            ))}
          </select>
        </Field>
        <Field label="Template set (optional)">
          <select
            value={templateSetId}
            onChange={(e) => setTemplateSetId(e.target.value)}
            className={selectCls}
          >
            <option value="">Default (all templates)</option>
            {(templateSets.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </Field>
        {run.isError && <ErrorText error={run.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!targetId || run.isPending} onClick={() => run.mutate()}>
            {run.isPending ? "Starting…" : "Run scan"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function ScansPage() {
  const me = useMe();
  const canRun = hasRole(me.data ?? undefined, "operator");
  const canCancel = canRun;
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const showActions = canCancel || canDelete;
  const [runOpen, setRunOpen] = useState(false);
  const qc = useQueryClient();

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.listScans(),
    refetchInterval: (q) => {
      const active = (q.state.data ?? []).some((s) => s.state === "queued" || s.state === "running");
      return active ? 2000 : false;
    },
  });

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["scans"] });
  const cancel = useMutation({ mutationFn: (id: string) => api.cancelScan(id), onSuccess: invalidate });
  const del = useMutation({ mutationFn: (id: string) => api.deleteScan(id), onSuccess: invalidate });
  const colCount = 6 + (showActions ? 1 : 0);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Scans</h1>
        {canRun && (
          <Button variant="primary" onClick={() => setRunOpen(true)}>
            Run scan
          </Button>
        )}
      </div>

      {scans.isLoading ? (
        <Spinner />
      ) : scans.isError ? (
        <ErrorText error={scans.error} />
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="px-3 py-2 font-medium">Scan</th>
                  <th className="px-3 py-2 font-medium">Target</th>
                  <th className="px-3 py-2 font-medium">State</th>
                  <th className="px-3 py-2 font-medium">Started</th>
                  <th className="px-3 py-2 font-medium">Finished</th>
                  <th className="px-3 py-2 font-medium">Nuclei</th>
                  {showActions && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(scans.data ?? []).map((s) => (
                  <tr
                    key={s.id}
                    className="border-b border-neutral-100 last:border-0 hover:bg-neutral-50 dark:border-neutral-800/60 dark:hover:bg-neutral-800/40"
                  >
                    <td className="px-3 py-2">
                      <Link to={`/scans/${s.id}`} className="font-mono text-xs text-indigo-600 hover:underline dark:text-indigo-400">
                        {s.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="px-3 py-2">
                      {s.target_name ? (
                        <span>
                          {s.target_name}
                          {s.target_host_count ? (
                            <span className="text-neutral-400">
                              {" "}
                              ({s.target_host_count} host{s.target_host_count === 1 ? "" : "s"})
                            </span>
                          ) : null}
                        </span>
                      ) : (
                        <span className="text-neutral-400">ad-hoc</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <StateBadge state={s.state} />
                    </td>
                    <td className="px-3 py-2 text-neutral-500">{new Date(s.created_at).toLocaleString()}</td>
                    <td className="px-3 py-2 text-neutral-500">
                      {s.finished_at ? new Date(s.finished_at).toLocaleString() : "—"}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-500">{s.nuclei_version || "—"}</td>
                    {showActions && (
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        {canCancel && (s.state === "queued" || s.state === "running") && (
                          <Button
                            variant="ghost"
                            disabled={cancel.isPending}
                            onClick={() => {
                              if (confirm(`Stop scan ${s.id.slice(0, 8)}?`)) cancel.mutate(s.id);
                            }}
                          >
                            Stop
                          </Button>
                        )}
                        {canDelete && s.state !== "queued" && s.state !== "running" && (
                          <Button
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            disabled={del.isPending}
                            onClick={() => {
                              if (confirm(`Delete scan ${s.id.slice(0, 8)}? This removes its findings occurrences and archived output.`))
                                del.mutate(s.id);
                            }}
                          >
                            Delete
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
                {(scans.data ?? []).length === 0 && (
                  <tr>
                    <td colSpan={colCount} className="px-3 py-8 text-center text-neutral-400">
                      No scans yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {runOpen && <RunScanModal onClose={() => setRunOpen(false)} />}
    </div>
  );
}
