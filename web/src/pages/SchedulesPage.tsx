import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type Schedule } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Select, Spinner } from "../components/ui";

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

function ScheduleModal({ existing, onClose }: { existing?: Schedule; onClose: () => void }) {
  const qc = useQueryClient();
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const templateSets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });

  const [name, setName] = useState(existing?.name ?? "");
  const [targetId, setTargetId] = useState(existing?.target_id ?? "");
  const [templateSetId, setTemplateSetId] = useState(existing?.template_set_id ?? "");
  const [cron, setCron] = useState(existing?.cron ?? "0 3 * * *");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [timeoutSec, setTimeoutSec] = useState(existing?.timeout_sec ? String(existing.timeout_sec) : "");

  const selectedTarget = (targets.data ?? []).find((t) => t.id === targetId);
  const timeoutNum = Number(timeoutSec);
  // Empty means "use the backend default" — only a non-empty value is validated.
  const timeoutInvalid = timeoutSec.trim() !== "" && (!Number.isInteger(timeoutNum) || timeoutNum <= 0);

  const save = useMutation({
    mutationFn: () => {
      const body: Partial<Schedule> = {
        name: name.trim(),
        target_id: targetId,
        template_set_id: templateSetId || undefined,
        cron: cron.trim(),
        enabled,
        timeout_sec: timeoutSec.trim() === "" ? undefined : timeoutNum,
      };
      return existing ? api.updateSchedule(existing.id, body) : api.createSchedule(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["schedules"] });
      onClose();
    },
  });

  const canSave = name.trim() && targetId && cron.trim() && !timeoutInvalid;

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title={existing ? "Edit schedule" : "New schedule"}>
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="nightly-prod" />
        </Field>
        <Field label="Target">
          <Select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="w-full">
            <option value="">Select a target…</option>
            {(targets.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Template set (optional — all templates if unset)">
          <Select value={templateSetId} onChange={(e) => setTemplateSetId(e.target.value)} className="w-full">
            <option value="">All templates</option>
            {(templateSets.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </Select>
        </Field>
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
        <Field label="Timeout (seconds, optional — default 600)">
          <Input
            type="number"
            min={1}
            value={timeoutSec}
            onChange={(e) => setTimeoutSec(e.target.value)}
            placeholder="600"
          />
        </Field>
        {selectedTarget && selectedTarget.host_count > 50 && (
          <p className="-mt-2 text-xs text-amber-700 dark:text-amber-400">
            {selectedTarget.host_count} hosts in scope — the default 10 min may not be enough; consider setting a
            longer timeout.
          </p>
        )}
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

  const q = useQuery({ queryKey: ["schedules"], queryFn: () => api.listSchedules() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const targetName = (id: string) => targets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8);

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["schedules"] });
  const del = useMutation({ mutationFn: (id: string) => api.deleteSchedule(id), onSuccess: invalidate });
  const toggle = useMutation({
    mutationFn: (s: Schedule) =>
      api.updateSchedule(s.id, {
        name: s.name,
        target_id: s.target_id,
        template_set_id: s.template_set_id || undefined,
        cron: s.cron,
        enabled: !s.enabled,
        timeout_sec: s.timeout_sec,
      }),
    onSuccess: invalidate,
  });
  const run = useMutation({ mutationFn: (id: string) => api.runSchedule(id), onSuccess: invalidate });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Schedules</h1>
          <p className="text-sm text-neutral-500">Cron-driven scans dispatched automatically by the backend.</p>
        </div>
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing("new")}>
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
                            <Button variant="ghost" onClick={() => setEditing(s)}>
                              Edit
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
                    <td colSpan={7} className="px-3 py-8 text-center text-neutral-400">
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
        <ScheduleModal existing={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}
