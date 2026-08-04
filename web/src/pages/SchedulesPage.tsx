import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type Schedule } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Select, Spinner } from "../components/ui";
import { duplicateName } from "../util";

// Common cron presets offered as one-click buttons in the editor.
const CRON_PRESETS: { label: string; cron: string }[] = [
  { label: "Hourly", cron: "0 * * * *" },
  { label: "Daily 03:00", cron: "0 3 * * *" },
  { label: "Weekly (Mon 03:00)", cron: "0 3 * * 1" },
  { label: "Every 15 min", cron: "*/15 * * * *" },
];

function fmt(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function ScheduleModal({
  existing,
  duplicate = false,
  existingNames,
  onClose,
}: {
  existing?: Schedule;
  duplicate?: boolean;
  existingNames: string[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const scanPolicies = useQuery({ queryKey: ["scan-policies"], queryFn: () => api.listScanPolicies() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });

  const [name, setName] = useState(
    existing ? (duplicate ? duplicateName(existing.name, existingNames) : existing.name) : "",
  );
  const [scanPolicyId, setScanPolicyId] = useState(existing?.scan_policy_id ?? "");
  const [targetId, setTargetId] = useState(existing?.target_id ?? "");
  const [cron, setCron] = useState(existing?.cron ?? "0 3 * * *");
  const [enabled, setEnabled] = useState(duplicate ? false : (existing?.enabled ?? true));

  const policies = scanPolicies.data ?? [];

  const save = useMutation({
    mutationFn: () => {
      const body: Partial<Schedule> = {
        name: name.trim(),
        scan_policy_id: scanPolicyId,
        target_id: targetId,
        cron: cron.trim(),
        enabled,
      };
      return existing && !duplicate ? api.updateSchedule(existing.id, body) : api.createSchedule(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["schedules"] });
      onClose();
    },
  });

  const canSave = name.trim() && scanPolicyId && targetId && cron.trim();

  return (
    <Modal
      open
      onOpenChange={(v) => !v && onClose()}
      title={duplicate ? "Duplicate schedule" : existing ? "Edit schedule" : "New schedule"}
    >
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="nightly-prod" />
        </Field>
        <Field label="Scan policy (templates + execution settings)">
          <Select value={scanPolicyId} onChange={(e) => setScanPolicyId(e.target.value)} className="w-full">
            <option value="">Select a scan policy…</option>
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </Field>
        {!scanPolicies.isLoading && policies.length === 0 && (
          <p className="-mt-2 text-xs text-amber-700 dark:text-amber-400">
            No scan policies yet — create one under Scan Policies first.
          </p>
        )}
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
        {!targets.isLoading && (targets.data ?? []).length === 0 && (
          <p className="-mt-2 text-xs text-amber-700 dark:text-amber-400">
            No approved targets yet — create one under Targets first.
          </p>
        )}
        <Field label="Cron (min hour day-of-month month day-of-week)">
          <Input value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 3 * * *" className="font-mono" />
        </Field>
        <div className="flex flex-wrap gap-1">
          {CRON_PRESETS.map((p) => (
            <button
              key={p.cron}
              type="button"
              onClick={() => setCron(p.cron)}
              className="rounded border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-800"
            >
              {p.label}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled (the ticker dispatches this schedule)
        </label>
        {save.isError && <ErrorText error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!canSave || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function SchedulesPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Schedule | "new" | null>(null);
  const [duplicating, setDuplicating] = useState(false);

  const q = useQuery({ queryKey: ["schedules"], queryFn: () => api.listSchedules() });
  const policies = useQuery({ queryKey: ["scan-policies"], queryFn: () => api.listScanPolicies() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const policyName = (id: string) => policies.data?.find((p) => p.id === id)?.name ?? id.slice(0, 8);
  const targetName = (id: string) => targets.data?.find((target) => target.id === id)?.name ?? id.slice(0, 8);

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["schedules"] });
  const del = useMutation({ mutationFn: (id: string) => api.deleteSchedule(id), onSuccess: invalidate });
  const toggle = useMutation({
    mutationFn: (s: Schedule) =>
      api.updateSchedule(s.id, {
        name: s.name,
        scan_policy_id: s.scan_policy_id,
        target_id: s.target_id,
        cron: s.cron,
        enabled: !s.enabled,
      }),
    onSuccess: invalidate,
  });
  const run = useMutation({ mutationFn: (id: string) => api.runSchedule(id), onSuccess: invalidate });
  const closeEditor = () => {
    setEditing(null);
    setDuplicating(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Schedules</h1>
          <p className="text-sm text-neutral-500">Cron-driven scans dispatched automatically by the backend.</p>
        </div>
        {canWrite && (
          <Button
            variant="primary"
            onClick={() => {
              setDuplicating(false);
              setEditing("new");
            }}
          >
            New schedule
          </Button>
        )}
      </div>

      {q.isLoading ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Scan policy</th>
                  <th className="px-3 py-2 font-medium">Target</th>
                  <th className="px-3 py-2 font-medium">Cron</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Next run</th>
                  <th className="px-3 py-2 font-medium">Last run</th>
                  {(canWrite || canDelete) && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((s) => (
                  <tr key={s.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{s.name}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">{policyName(s.scan_policy_id)}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">{targetName(s.target_id)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-600 dark:text-neutral-400">{s.cron}</td>
                    <td className="px-3 py-2">
                      {s.enabled ? (
                        <span className="inline-block rounded bg-green-100 px-1.5 py-0.5 text-xs font-medium text-green-800 dark:bg-green-950 dark:text-green-300">
                          enabled
                        </span>
                      ) : (
                        <span className="inline-block rounded bg-neutral-200 px-1.5 py-0.5 text-xs font-medium text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400">
                          disabled
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-neutral-500">{s.enabled ? fmt(s.next_run_at) : "—"}</td>
                    <td className="px-3 py-2 text-xs text-neutral-500">{fmt(s.last_run_at)}</td>
                    {(canWrite || canDelete) && (
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        {canWrite && (
                          <>
                            <Button
                              variant="ghost"
                              disabled={run.isPending}
                              onClick={() => run.mutate(s.id)}
                              title="Dispatch now, off-schedule"
                            >
                              Run now
                            </Button>
                            <Button variant="ghost" disabled={toggle.isPending} onClick={() => toggle.mutate(s)}>
                              {s.enabled ? "Disable" : "Enable"}
                            </Button>
                            <Button
                              variant="ghost"
                              onClick={() => {
                                setDuplicating(false);
                                setEditing(s);
                              }}
                            >
                              Edit
                            </Button>
                            <Button
                              variant="ghost"
                              onClick={() => {
                                setDuplicating(true);
                                setEditing(s);
                              }}
                            >
                              Duplicate
                            </Button>
                          </>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            onClick={() => {
                              if (confirm(`Delete schedule "${s.name}"?`)) del.mutate(s.id);
                            }}
                          >
                            Delete
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
                {(q.data ?? []).length === 0 && (
                  <tr>
                    <td colSpan={7 + (canWrite || canDelete ? 1 : 0)} className="px-3 py-8 text-center text-neutral-400">
                      No schedules yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <ScheduleModal
          existing={editing === "new" ? undefined : editing}
          duplicate={duplicating}
          existingNames={(q.data ?? []).map((schedule) => schedule.name)}
          onClose={closeEditor}
        />
      )}
    </div>
  );
}
