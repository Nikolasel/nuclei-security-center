import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type ScanPolicy } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Select, Spinner, Textarea } from "../components/ui";

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

// The default port set naabu scans when discovery_ports is left blank.
const DISCOVERY_DEFAULT_PORTS = "top-1000";

// portsInvalid mirrors the backend's validatePortSpec (internal/backend/validate.go):
// comma-separated single ports (N) or inclusive ranges (N-M), all within 1-65535.
// Empty = the default port set, always valid. Client-side so a typo is caught
// before the save round-trip; the backend re-validates (discovery fails closed).
function portsInvalid(s: string): boolean {
  const spec = s.trim();
  if (spec === "") return false;
  const port = (p: string) => {
    const n = Number(p.trim());
    return Number.isInteger(n) && n >= 1 && n <= 65535;
  };
  return spec.split(",").some((tok) => {
    const t = tok.trim();
    if (t === "") return true;
    const [lo, hi, ...rest] = t.split("-");
    if (rest.length > 0) return true;
    if (!port(lo)) return true;
    if (hi === undefined) return false; // single port
    return !port(hi) || Number(hi) < Number(lo);
  });
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
  // Discovery (#86) defaults ON for a new policy (matches the backend default).
  const [discoveryEnabled, setDiscoveryEnabled] = useState(existing?.discovery_enabled ?? true);
  // "" = the node's NAABU_SCAN_TYPE default; else "syn" / "connect".
  const [discoveryScanType, setDiscoveryScanType] = useState(existing?.discovery_scan_type ?? "");
  const [discoveryPorts, setDiscoveryPorts] = useState(existing?.discovery_ports ?? "");
  const [discoveryTimeoutSec, setDiscoveryTimeoutSec] = useState(
    existing?.discovery_timeout_sec != null ? String(existing.discovery_timeout_sec) : "",
  );
  const [discoveryRate, setDiscoveryRate] = useState(
    existing?.discovery_rate != null ? String(existing.discovery_rate) : "",
  );
  const [discoveryProbeTimeoutMs, setDiscoveryProbeTimeoutMs] = useState(
    existing?.discovery_probe_timeout_ms != null ? String(existing.discovery_probe_timeout_ms) : "",
  );
  const [discoveryRetries, setDiscoveryRetries] = useState(
    existing?.discovery_retries != null ? String(existing.discovery_retries) : "",
  );

  const anyInvalid =
    knobInvalid(rateLimit) ||
    knobInvalid(concurrency) ||
    knobInvalid(timeoutSec) ||
    knobInvalid(maxHostError) ||
    (discoveryEnabled &&
      (portsInvalid(discoveryPorts) ||
        knobInvalid(discoveryTimeoutSec) ||
        knobInvalid(discoveryRate) ||
        knobInvalid(discoveryProbeTimeoutMs) ||
        knobInvalid(discoveryRetries)));
  const canSave = name.trim() !== "" && targetId !== "" && templateSetId !== "" && !anyInvalid;

  const save = useMutation({
    mutationFn: () => {
      const body: Partial<ScanPolicy> = {
        name: name.trim(),
        target_id: targetId,
        template_set_id: templateSetId,
        rate_limit: parseKnob(rateLimit),
        concurrency: parseKnob(concurrency),
        timeout_sec: parseKnob(timeoutSec),
        max_host_error: parseKnob(maxHostError),
        discovery_enabled: discoveryEnabled,
        discovery_scan_type: discoveryEnabled ? discoveryScanType || undefined : undefined,
        discovery_ports: discoveryEnabled ? discoveryPorts.trim() || undefined : undefined,
        discovery_timeout_sec: discoveryEnabled ? parseKnob(discoveryTimeoutSec) : null,
        discovery_rate: discoveryEnabled ? parseKnob(discoveryRate) : null,
        discovery_probe_timeout_ms: discoveryEnabled ? parseKnob(discoveryProbeTimeoutMs) : null,
        discovery_retries: discoveryEnabled ? parseKnob(discoveryRetries) : null,
      };
      return existing ? api.updateScanPolicy(existing.id, body) : api.createScanPolicy(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scan-policies"] });
      onClose();
    },
  });

  return (
    <Modal
      open
      onOpenChange={(v) => !v && onClose()}
      title={existing ? "Edit scan policy" : "New scan policy"}
      size="wide"
    >
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
        <Field label="Template set">
          <Select value={templateSetId} onChange={(e) => setTemplateSetId(e.target.value)} className="w-full">
            <option value="">Select a template set…</option>
            {(templateSets.data ?? []).map((t) => (
              <option key={t.id} value={t.id} disabled={!t.dynamic_all && t.member_count === 0}>
                {t.name}
                {t.dynamic_all
                  ? ` (all ${t.member_count} active · dynamic)`
                  : t.member_count === 0
                    ? " (empty)"
                    : ` (${t.member_count} templates)`}
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
        <div className="border-t border-neutral-200 pt-4 dark:border-neutral-800">
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-1"
              checked={discoveryEnabled}
              onChange={(e) => setDiscoveryEnabled(e.target.checked)}
            />
            <span className="text-sm">
              <span className="font-medium">Port discovery (naabu) before Nuclei</span>
              <span className="block text-xs text-neutral-500">
                Runs a fast port scan first, so Nuclei only probes live host:port pairs — the win for
                CIDR-scoped targets. It fails closed: if discovery errors, the scan fails, so turn this off
                when naabu is unavailable.
              </span>
            </span>
          </label>
          {discoveryEnabled && (
            <div className="mt-3 space-y-4">
              <Field label="Scan mode">
                <Select
                  value={discoveryScanType}
                  onChange={(e) => setDiscoveryScanType(e.target.value)}
                  className="max-w-xs"
                >
                  <option value="">Node default (NAABU_SCAN_TYPE)</option>
                  <option value="syn">SYN + host discovery (faster; needs raw sockets)</option>
                  <option value="connect">Connect (unprivileged; no host discovery)</option>
                </Select>
                <span className="mt-1 block text-xs text-neutral-500">
                  SYN prunes dead hosts before scanning (the win on sparse ranges) but needs the node's
                  raw-socket capability + libpcap — it fails closed on a node without them. Connect works
                  anywhere but scans every host.
                </span>
              </Field>
              <Field label="Ports (blank = top-1000)">
                <Textarea
                  rows={2}
                  value={discoveryPorts}
                  onChange={(e) => setDiscoveryPorts(e.target.value)}
                  placeholder={DISCOVERY_DEFAULT_PORTS + " · e.g. 22,80,443,8000-9000,9200-9300"}
                  className="min-h-[2.5rem] resize-y"
                />
              </Field>
              {portsInvalid(discoveryPorts) && (
                <p className="text-xs text-red-600 dark:text-red-400">
                  Ports must be comma-separated single ports or ranges (e.g.{" "}
                  <span className="font-mono">80,443,8000-9000</span>), each within 1–65535.
                </p>
              )}
              <Field label="Discovery timeout (seconds)">
                <Input
                  type="number"
                  min={1}
                  value={discoveryTimeoutSec}
                  onChange={(e) => setDiscoveryTimeoutSec(e.target.value)}
                  placeholder="300"
                  className="max-w-xs"
                />
              </Field>
              <p className="text-xs text-neutral-500">
                Tuning (blank = naabu default). Lower values scan faster but can miss slow-responding or
                (in SYN mode) lossy ports — leave blank unless discovery is too slow on your range.
              </p>
              <div className="grid grid-cols-3 gap-4">
                <Field label="Rate (pkts/s)">
                  <Input
                    type="number"
                    min={1}
                    value={discoveryRate}
                    onChange={(e) => setDiscoveryRate(e.target.value)}
                    placeholder="1000"
                  />
                </Field>
                <Field label="Probe timeout (ms)">
                  <Input
                    type="number"
                    min={1}
                    value={discoveryProbeTimeoutMs}
                    onChange={(e) => setDiscoveryProbeTimeoutMs(e.target.value)}
                    placeholder="1000"
                  />
                </Field>
                <Field label="Retries">
                  <Input
                    type="number"
                    min={1}
                    value={discoveryRetries}
                    onChange={(e) => setDiscoveryRetries(e.target.value)}
                    placeholder="3"
                  />
                </Field>
              </div>
            </div>
          )}
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

// discoveryCell summarizes a policy's naabu pre-pass: off, or on with its scan
// mode (node default when unset) and port set (top-1000 when unset).
function discoveryCell(p: ScanPolicy) {
  if (p.discovery_enabled === false) return <span className="text-neutral-400">off</span>;
  const mode = p.discovery_scan_type?.trim();
  const ports = p.discovery_ports?.trim() || "top-1000";
  const summary = `${mode ? `${mode} · ` : ""}${ports}`;
  return (
    <span className="inline-block max-w-80 truncate align-bottom font-mono text-xs" title={summary}>
      {summary}
    </span>
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
    id ? (templateSets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8)) : "missing";
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
                  <th className="px-3 py-2 font-medium">Discovery</th>
                  {(canWrite || canDelete) && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((p) => (
                  <tr key={p.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{p.name}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">{targetName(p.target_id)}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">
                      {templateSetName(p.template_set_id)}
                    </td>
                    <td className="px-3 py-2">{knob(p.rate_limit)}</td>
                    <td className="px-3 py-2">{knob(p.concurrency)}</td>
                    <td className="px-3 py-2">{knob(p.timeout_sec)}</td>
                    <td className="px-3 py-2">{knob(p.max_host_error)}</td>
                    <td className="px-3 py-2">{discoveryCell(p)}</td>
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
                    <td colSpan={9} className="px-3 py-8 text-center text-neutral-400">
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
