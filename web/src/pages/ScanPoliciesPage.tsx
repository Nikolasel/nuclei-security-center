import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type ScanPolicy } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Select, Spinner } from "../components/ui";

// The built-in defaults each knob falls back to when a policy leaves it unset.
// Mirrors the backend's defaultOptions() (internal/backend/http.go) plus Nuclei's
// own -max-host-error default; shown as the input placeholder, never sent.
const DEFAULTS = {
  rate_limit: 150,
  concurrency: 25,
  timeout_sec: 600,
  max_host_error: 30,
} as const;

// parseKnob turns an input string into the value the API expects: null (unset —
// use the built-in default) for an empty box, a number otherwise. NaN is left as
// null so a half-typed field never blocks; validation gates the Save button.
function parseKnob(s: string): number | null {
  if (s.trim() === "") return null;
  const n = Number(s);
  return Number.isInteger(n) ? n : null;
}

function knobInvalid(s: string): boolean {
  if (s.trim() === "") return false; // empty = use default, always fine
  const n = Number(s);
  return !Number.isInteger(n) || n <= 0;
}

function ScanPolicyModal({ existing, onClose }: { existing?: ScanPolicy; onClose: () => void }) {
  const qc = useQueryClient();
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const templateSets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const [name, setName] = useState(existing?.name ?? "");
  const [targetId, setTargetId] = useState(existing?.target_id ?? "");
  const [templateSetId, setTemplateSetId] = useState(existing?.template_set_id ?? "");
  const [rateLimit, setRateLimit] = useState(existing?.rate_limit != null ? String(existing.rate_limit) : "");
  const [concurrency, setConcurrency] = useState(
    existing?.concurrency != null ? String(existing.concurrency) : "",
  );
  const [timeoutSec, setTimeoutSec] = useState(
    existing?.timeout_sec != null ? String(existing.timeout_sec) : "",
  );
  const [maxHostError, setMaxHostError] = useState(
    existing?.max_host_error != null ? String(existing.max_host_error) : "",
  );

  const anyInvalid =
    knobInvalid(rateLimit) || knobInvalid(concurrency) || knobInvalid(timeoutSec) || knobInvalid(maxHostError);
  const canSave = name.trim() !== "" && targetId !== "" && !anyInvalid;

  const save = useMutation({
    mutationFn: () => {
      const body: Partial<ScanPolicy> = {
        name: name.trim(),
        target_id: targetId,
        template_set_id: templateSetId || undefined,
        rate_limit: parseKnob(rateLimit),
        concurrency: parseKnob(concurrency),
        timeout_sec: parseKnob(timeoutSec),
        max_host_error: parseKnob(maxHostError),
      };
      return existing ? api.updateScanPolicy(existing.id, body) : api.createScanPolicy(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scan-policies"] });
      onClose();
    },
  });

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title={existing ? "Edit scan policy" : "New scan policy"}>
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="fragile-device" />
        </Field>
        <Field label="Target (scope allowlist)">
          <Select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="w-full">
            <option value="">Select a target…</option>
            {(targets.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.host_count} host{t.host_count === 1 ? "" : "s"})
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
        <p className="text-xs text-neutral-500">
          Leave a knob blank to use its built-in default. Raise <span className="font-mono">max-host-error</span>{" "}
          (and/or lower the rate) for fragile devices that Nuclei would otherwise abandon mid-scan.
        </p>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Rate limit (req/s)">
            <Input
              type="number"
              min={1}
              value={rateLimit}
              onChange={(e) => setRateLimit(e.target.value)}
              placeholder={String(DEFAULTS.rate_limit)}
            />
          </Field>
          <Field label="Concurrency">
            <Input
              type="number"
              min={1}
              value={concurrency}
              onChange={(e) => setConcurrency(e.target.value)}
              placeholder={String(DEFAULTS.concurrency)}
            />
          </Field>
          <Field label="Timeout (seconds)">
            <Input
              type="number"
              min={1}
              value={timeoutSec}
              onChange={(e) => setTimeoutSec(e.target.value)}
              placeholder={String(DEFAULTS.timeout_sec)}
            />
          </Field>
          <Field label="Max host error">
            <Input
              type="number"
              min={1}
              value={maxHostError}
              onChange={(e) => setMaxHostError(e.target.value)}
              placeholder={String(DEFAULTS.max_host_error)}
            />
          </Field>
        </div>
        {anyInvalid && (
          <p className="text-xs text-red-600 dark:text-red-400">
            Each value must be a positive whole number (or blank to use the default).
          </p>
        )}
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

// knob renders a policy value or a muted "default" placeholder when unset.
function knob(v: number | null | undefined) {
  return v != null ? (
    <span className="font-mono">{v}</span>
  ) : (
    <span className="text-neutral-400">default</span>
  );
}

export function ScanPoliciesPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [editing, setEditing] = useState<ScanPolicy | "new" | null>(null);

  const q = useQuery({ queryKey: ["scan-policies"], queryFn: () => api.listScanPolicies() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const templateSets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const targetName = (id: string) => targets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8);
  const templateSetName = (id?: string) =>
    id ? (templateSets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8)) : null;
  const del = useMutation({
    mutationFn: (id: string) => api.deleteScanPolicy(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["scan-policies"] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Scan Policies</h1>
          <p className="text-sm text-neutral-500">
            The reusable scan configuration — target, template set, and execution knobs. Every scan and
            schedule runs a policy.
          </p>
        </div>
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing("new")}>
            New scan policy
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
                  <th className="px-3 py-2 font-medium">Template set</th>
                  <th className="px-3 py-2 font-medium">Rate limit</th>
                  <th className="px-3 py-2 font-medium">Concurrency</th>
                  <th className="px-3 py-2 font-medium">Timeout (s)</th>
                  <th className="px-3 py-2 font-medium">Max host error</th>
                  {(canWrite || canDelete) && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((p) => (
                  <tr key={p.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{p.name}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">{targetName(p.target_id)}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">
                      {templateSetName(p.template_set_id) ?? <span className="text-neutral-400">all templates</span>}
                    </td>
                    <td className="px-3 py-2">{knob(p.rate_limit)}</td>
                    <td className="px-3 py-2">{knob(p.concurrency)}</td>
                    <td className="px-3 py-2">{knob(p.timeout_sec)}</td>
                    <td className="px-3 py-2">{knob(p.max_host_error)}</td>
                    {(canWrite || canDelete) && (
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        {canWrite && (
                          <Button variant="ghost" onClick={() => setEditing(p)}>
                            Edit
                          </Button>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            onClick={() => {
                              if (confirm(`Delete scan policy "${p.name}"?`)) del.mutate(p.id);
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
                    <td colSpan={8} className="px-3 py-8 text-center text-neutral-400">
                      No scan policies yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <ScanPolicyModal existing={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}
