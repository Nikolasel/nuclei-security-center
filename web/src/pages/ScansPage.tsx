import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { hasRole, useMe } from "../auth";
import {
  Button,
  Card,
  ErrorText,
  Field,
  FormHint,
  linkClass,
  Modal,
  ModalActions,
  Muted,
  Page,
  PageHeader,
  ProgressBar,
  RowActions,
  Select,
  Spinner,
  StateBadge,
  Table,
  TableEmpty,
  Td,
  Th,
  THead,
  TRow,
  useConfirm,
} from "../components/ui";
import { ImportBundleModal } from "./ImportBundleModal";

function RunScanModal({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const scanPolicies = useQuery({ queryKey: ["scan-policies"], queryFn: () => api.listScanPolicies() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const [scanPolicyId, setScanPolicyId] = useState("");
  const [targetId, setTargetId] = useState("");

  const targetName = (id: string) => targets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8);
  const selectedPolicy = (scanPolicies.data ?? []).find((p) => p.id === scanPolicyId);
  const policies = scanPolicies.data ?? [];

  const run = useMutation({
    mutationFn: () => api.createScan({ scan_policy_id: scanPolicyId, target_id: targetId }),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["scans"] });
      onClose();
      navigate(`/scans/${res.scan_id}`);
    },
  });

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title="Run scan">
      <div className="space-y-4">
        <Field label="Scan policy">
          <Select value={scanPolicyId} onChange={(e) => setScanPolicyId(e.target.value)} className="w-full">
            <option value="">Select a scan policy…</option>
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Target (approved scope)">
          <Select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="w-full">
            <option value="">Select a target…</option>
            {(targets.data ?? []).map((target) => (
              <option key={target.id} value={target.id}>
                {target.name} ({target.host_count} host{target.host_count === 1 ? "" : "s"})
              </option>
            ))}
          </Select>
        </Field>
        {selectedPolicy && (
          <div className="space-y-1 text-xs text-neutral-500">
            <p>
              Runs the <span className="font-medium">{selectedPolicy.name}</span> policy
              {targetId ? (
                <>
                  {" "}against <span className="font-medium">{targetName(targetId)}</span>
                </>
              ) : null}
              .
            </p>
            <p>Confirm its discovery mode, rate, and timeouts are appropriate for the selected target.</p>
          </div>
        )}
        {!scanPolicies.isLoading && policies.length === 0 && (
          <FormHint tone="warning">No scan policies yet — create one under Scan policies first.</FormHint>
        )}
        {!targets.isLoading && (targets.data ?? []).length === 0 && (
          <FormHint tone="warning">No approved targets yet — create one under Targets before running a scan.</FormHint>
        )}
        {run.isError && <ErrorText error={run.error} />}
        <ModalActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!scanPolicyId || !targetId || run.isPending} onClick={() => run.mutate()}>
            {run.isPending ? "Starting…" : "Run scan"}
          </Button>
        </ModalActions>
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
  const [importOpen, setImportOpen] = useState(false);
  const qc = useQueryClient();
  const confirm = useConfirm();

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
  const colCount = 7 + (showActions ? 1 : 0);

  return (
    <Page>
      <PageHeader
        title="Scans"
        description="On-demand and scheduled scan runs, newest first."
        actions={
          canRun && (
            <>
              <Button onClick={() => setImportOpen(true)}>Import bundle</Button>
              <Button variant="primary" onClick={() => setRunOpen(true)}>
                Run scan
              </Button>
            </>
          )
        }
      />

      {(cancel.isError || del.isError) && <ErrorText error={cancel.error ?? del.error} />}

      {scans.isLoading ? (
        <Spinner />
      ) : scans.isError ? (
        <ErrorText error={scans.error} />
      ) : (
        <Card>
          <Table>
            <THead>
              <Th>Scan</Th>
              <Th>Target</Th>
              <Th>Node</Th>
              <Th>State</Th>
              <Th>Started</Th>
              <Th>Finished</Th>
              <Th>Nuclei</Th>
              {showActions && <Th aria-label="Actions" />}
            </THead>
            <tbody>
              {(scans.data ?? []).map((s) => {
                const active = s.state === "queued" || s.state === "running";
                const short = s.id.slice(0, 8);
                return (
                  <TRow key={s.id}>
                    <Td>
                      <Link to={`/scans/${s.id}`} className={`font-mono text-xs ${linkClass}`}>
                        {short}
                      </Link>
                    </Td>
                    <Td>
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
                        <Muted>ad-hoc</Muted>
                      )}
                    </Td>
                    <Td className="text-neutral-600 dark:text-neutral-300">{s.node_name || <Muted />}</Td>
                    <Td>
                      <StateBadge state={s.state} />
                      {s.state === "running" && s.progress && (
                        <div className="mt-1 w-40">
                          <ProgressBar percent={s.progress.percent} />
                        </div>
                      )}
                    </Td>
                    <Td className="whitespace-nowrap text-neutral-500">{new Date(s.created_at).toLocaleString()}</Td>
                    <Td className="whitespace-nowrap text-neutral-500">
                      {s.finished_at ? new Date(s.finished_at).toLocaleString() : <Muted />}
                    </Td>
                    <Td className="font-mono text-xs text-neutral-500">{s.nuclei_version || <Muted />}</Td>
                    {showActions && (
                      <RowActions
                        label={`scan ${short}`}
                        actions={[
                          {
                            label: "Stop",
                            primary: true,
                            hidden: !canCancel || !active,
                            disabled: cancel.isPending,
                            onSelect: async () => {
                              if (
                                await confirm({
                                  title: `Stop scan ${short}?`,
                                  description: "The scanner node cancels the run. Results collected so far are not ingested.",
                                  confirmLabel: "Stop scan",
                                })
                              )
                                cancel.mutate(s.id);
                            },
                          },
                          {
                            label: "Delete",
                            danger: true,
                            hidden: !canDelete || active,
                            disabled: del.isPending,
                            onSelect: async () => {
                              if (
                                await confirm({
                                  title: `Delete scan ${short}?`,
                                  description:
                                    "This removes its finding occurrences and archived output. Finding lifecycles are recomputed from the scans that remain.",
                                  confirmLabel: "Delete scan",
                                })
                              )
                                del.mutate(s.id);
                            },
                          },
                        ]}
                      />
                    )}
                  </TRow>
                );
              })}
              {(scans.data ?? []).length === 0 && <TableEmpty colSpan={colCount}>No scans yet.</TableEmpty>}
            </tbody>
          </Table>
        </Card>
      )}

      {runOpen && <RunScanModal onClose={() => setRunOpen(false)} />}
      {importOpen && <ImportBundleModal onClose={() => setImportOpen(false)} />}
    </Page>
  );
}
