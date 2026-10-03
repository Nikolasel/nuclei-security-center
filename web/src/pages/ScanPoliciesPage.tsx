import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type ScanPolicy } from "../api";
import { hasRole, useMe } from "../auth";
import {
  Button,
  Card,
  Checkbox,
  ErrorText,
  Field,
  FormHint,
  FormSection,
  Input,
  Modal,
  ModalActions,
  Muted,
  Page,
  PageHeader,
  RowActions,
  Select,
  Spinner,
  Table,
  TableEmpty,
  Td,
  Textarea,
  Th,
  THead,
  TRow,
  useConfirm,
} from "../components/ui";
import { duplicateName } from "../util";

// The built-in defaults each knob falls back to when a policy leaves it unset.
// Mirrors the backend's defaultOptions() (internal/backend/http.go) plus Nuclei's
// own -max-host-error / -response-size-* defaults; shown as the input
// placeholder, never sent.
const DEFAULTS = {
  rate_limit: 150,
  concurrency: 25,
  timeout_sec: 600,
  max_host_error: 30,
  response_size_read: 10485760,
  response_size_save: 1048576,
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

function parseRecipients(s: string): string[] {
  return s
    .split(/[,;\n]+/)
    .map((p) => p.trim())
    .filter(Boolean);
}

function recipientsInvalid(s: string): boolean {
  return parseRecipients(s).some((addr) => !addr.includes("@") || addr.includes(" "));
}

function ScanPolicyModal({
  existing,
  duplicate = false,
  existingNames,
  onClose,
}: {
  existing?: ScanPolicy;
  duplicate?: boolean;
  existingNames: string[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const templateSets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const [name, setName] = useState(
    existing ? (duplicate ? duplicateName(existing.name, existingNames) : existing.name) : "",
  );
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
  const [responseSizeRead, setResponseSizeRead] = useState(
    existing?.response_size_read != null ? String(existing.response_size_read) : "",
  );
  const [responseSizeSave, setResponseSizeSave] = useState(
    existing?.response_size_save != null ? String(existing.response_size_save) : "",
  );
  // Discovery (#86) defaults ON for a new policy (matches the backend default).
  const [discoveryEnabled, setDiscoveryEnabled] = useState(existing?.discovery_enabled ?? true);
  // "" = the node's NAABU_SCAN_TYPE default; else "syn" / "connect".
  const [discoveryScanType, setDiscoveryScanType] = useState(existing?.discovery_scan_type ?? "");
  // null = scan-mode default (SYN on / connect off); true/false forces the
  // independent host-discovery pass on/off.
  const [discoveryHostDiscovery, setDiscoveryHostDiscovery] = useState<boolean | null>(
    existing?.discovery_host_discovery ?? null,
  );
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
  const [notifyEnabled, setNotifyEnabled] = useState(existing?.notify_enabled === true);
  const [notifyRecipients, setNotifyRecipients] = useState((existing?.notify_recipients ?? []).join(", "));
  const [notifyMinSeverity, setNotifyMinSeverity] = useState(existing?.notify_min_severity ?? "");

  const anyInvalid =
    knobInvalid(rateLimit) ||
    knobInvalid(concurrency) ||
    knobInvalid(timeoutSec) ||
    knobInvalid(maxHostError) ||
    knobInvalid(responseSizeRead) ||
    knobInvalid(responseSizeSave) ||
    (discoveryEnabled &&
      (portsInvalid(discoveryPorts) ||
        knobInvalid(discoveryTimeoutSec) ||
        knobInvalid(discoveryRate) ||
        knobInvalid(discoveryProbeTimeoutMs) ||
        knobInvalid(discoveryRetries))) ||
    recipientsInvalid(notifyRecipients);
  const canSave = name.trim() !== "" && templateSetId !== "" && !anyInvalid;

  const save = useMutation({
    mutationFn: () => {
      const body: Partial<ScanPolicy> = {
        name: name.trim(),
        template_set_id: templateSetId,
        rate_limit: parseKnob(rateLimit),
        concurrency: parseKnob(concurrency),
        timeout_sec: parseKnob(timeoutSec),
        max_host_error: parseKnob(maxHostError),
        response_size_read: parseKnob(responseSizeRead),
        response_size_save: parseKnob(responseSizeSave),
        discovery_enabled: discoveryEnabled,
        discovery_scan_type: discoveryEnabled ? discoveryScanType || undefined : undefined,
        // Explicit null clears a persisted override when the tri-state is back
        // at the scan-mode default; the other discovery knobs are plain tunings.
        discovery_host_discovery: discoveryEnabled ? discoveryHostDiscovery : null,
        discovery_ports: discoveryEnabled ? discoveryPorts.trim() || undefined : undefined,
        discovery_timeout_sec: discoveryEnabled ? parseKnob(discoveryTimeoutSec) : null,
        discovery_rate: discoveryEnabled ? parseKnob(discoveryRate) : null,
        discovery_probe_timeout_ms: discoveryEnabled ? parseKnob(discoveryProbeTimeoutMs) : null,
        discovery_retries: discoveryEnabled ? parseKnob(discoveryRetries) : null,
        notify_enabled: notifyEnabled,
        notify_recipients: parseRecipients(notifyRecipients),
        notify_min_severity: notifyMinSeverity || undefined,
      };
      return existing && !duplicate ? api.updateScanPolicy(existing.id, body) : api.createScanPolicy(body);
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
      title={duplicate ? "Duplicate scan policy" : existing ? "Edit scan policy" : "New scan policy"}
      size="wide"
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" required>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="fragile-device" className="w-full" />
          </Field>
          <Field label="Template set" required>
            <Select value={templateSetId} onChange={(e) => setTemplateSetId(e.target.value)} className="w-full">
              <option value="">Select a template set…</option>
              {(templateSets.data ?? []).map((t) => (
                <option key={t.id} value={t.id} disabled={t.mode === "exact" && t.member_count === 0}>
                  {t.name}
                  {t.mode === "all"
                    ? ` (all ${t.member_count} active)`
                    : t.mode === "exclude"
                      ? ` (all ${t.member_count} active · ${t.exclusion_count} excluded)`
                    : t.member_count === 0
                      ? " (empty)"
                      : ` (${t.member_count} templates)`}
                </option>
              ))}
            </Select>
          </Field>
        </div>

        <FormSection title="Nuclei execution">
          <FormHint>
            Leave a knob blank to use its built-in default. Raise <span className="font-mono">max-host-error</span>{" "}
            (and/or lower the rate) for fragile devices that Nuclei would otherwise abandon mid-scan.
          </FormHint>
          <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Rate limit (req/s)">
            <Input
              type="number"
              min={1}
              value={rateLimit}
              onChange={(e) => setRateLimit(e.target.value)}
              placeholder={String(DEFAULTS.rate_limit)}
              className="w-full"
            />
          </Field>
          <Field label="Concurrency">
            <Input
              type="number"
              min={1}
              value={concurrency}
              onChange={(e) => setConcurrency(e.target.value)}
              placeholder={String(DEFAULTS.concurrency)}
              className="w-full"
            />
          </Field>
          <Field label="Timeout (seconds)">
            <Input
              type="number"
              min={1}
              value={timeoutSec}
              onChange={(e) => setTimeoutSec(e.target.value)}
              placeholder={String(DEFAULTS.timeout_sec)}
              className="w-full"
            />
          </Field>
          <Field label="Max host error">
            <Input
              type="number"
              min={1}
              value={maxHostError}
              onChange={(e) => setMaxHostError(e.target.value)}
              placeholder={String(DEFAULTS.max_host_error)}
              className="w-full"
            />
          </Field>
          <Field label="Response size read (bytes)" hint="Max bytes read per response (nuclei -response-size-read, default 10 MiB). Lower to bound heap on large/CDN responses.">
            <Input
              type="number"
              min={1}
              value={responseSizeRead}
              onChange={(e) => setResponseSizeRead(e.target.value)}
              placeholder={String(DEFAULTS.response_size_read)}
              className="w-full"
            />
          </Field>
          <Field label="Response size save (bytes)" hint="Max bytes kept for output (nuclei -response-size-save, default 1 MiB).">
            <Input
              type="number"
              min={1}
              value={responseSizeSave}
              onChange={(e) => setResponseSizeSave(e.target.value)}
              placeholder={String(DEFAULTS.response_size_save)}
              className="w-full"
            />
          </Field>
          </div>
        </FormSection>

        <FormSection title="Port discovery">
          <Checkbox
            label="Run naabu port discovery before Nuclei"
            description="Runs a fast port scan first, so Nuclei only probes live host:port pairs — the win for CIDR-scoped targets. It fails closed: if discovery errors, the scan fails, so turn this off when naabu is unavailable."
            checked={discoveryEnabled}
            onChange={setDiscoveryEnabled}
          />
          {discoveryEnabled && (
            <div className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field
                  label="Scan mode"
                  hint="SYN needs the node's raw-socket capability + libpcap; connect is unprivileged."
                >
                  <Select
                    value={discoveryScanType}
                    onChange={(e) => setDiscoveryScanType(e.target.value)}
                    className="w-full"
                  >
                    <option value="">Node default (NAABU_SCAN_TYPE)</option>
                    <option value="syn">SYN (needs raw sockets)</option>
                    <option value="connect">Connect (unprivileged)</option>
                  </Select>
                </Field>
                <Field
                  label="Host discovery"
                  hint="Identify alive hosts first, then port-scan only those. Uses the node's SYN/raw-socket probes."
                >
                  <Select
                    value={discoveryHostDiscovery == null ? "" : discoveryHostDiscovery ? "on" : "off"}
                    onChange={(e) =>
                      setDiscoveryHostDiscovery(e.target.value === "" ? null : e.target.value === "on")
                    }
                    className="w-full"
                  >
                    <option value="">Scan-mode default (SYN on · connect off)</option>
                    <option value="on">Always on (extra discovery pass)</option>
                    <option value="off">Always off (scan every host)</option>
                  </Select>
                </Field>
              </div>
              <Field
                label="Ports"
                hint="Blank scans the top-1000 ports."
                error={
                  portsInvalid(discoveryPorts) && (
                    <>
                      Ports must be comma-separated single ports or ranges (e.g.{" "}
                      <span className="font-mono">80,443,8000-9000</span>), each within 1–65535.
                    </>
                  )
                }
              >
                <Textarea
                  rows={2}
                  value={discoveryPorts}
                  onChange={(e) => setDiscoveryPorts(e.target.value)}
                  placeholder={DISCOVERY_DEFAULT_PORTS + " · e.g. 22,80,443,8000-9000,9200-9300"}
                  className="min-h-[2.5rem]"
                />
              </Field>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Discovery timeout (seconds)" hint="Discovery's own budget, separate from the Nuclei timeout.">
                  <Input
                    type="number"
                    min={1}
                    value={discoveryTimeoutSec}
                    onChange={(e) => setDiscoveryTimeoutSec(e.target.value)}
                    placeholder="300"
                    className="w-full"
                  />
                </Field>
              </div>
              <FormHint>
                Tuning (blank = naabu default). Lower values scan faster but can miss slow-responding or
                (in SYN mode) lossy ports — leave blank unless discovery is too slow on your range.
              </FormHint>
              <div className="grid gap-4 sm:grid-cols-3">
                <Field label="Rate (pkts/s)">
                  <Input
                    type="number"
                    min={1}
                    value={discoveryRate}
                    onChange={(e) => setDiscoveryRate(e.target.value)}
                    placeholder="1000"
                    className="w-full"
                  />
                </Field>
                <Field label="Probe timeout (ms)">
                  <Input
                    type="number"
                    min={1}
                    value={discoveryProbeTimeoutMs}
                    onChange={(e) => setDiscoveryProbeTimeoutMs(e.target.value)}
                    placeholder="1000"
                    className="w-full"
                  />
                </Field>
                <Field label="Retries">
                  <Input
                    type="number"
                    min={1}
                    value={discoveryRetries}
                    onChange={(e) => setDiscoveryRetries(e.target.value)}
                    placeholder="3"
                    className="w-full"
                  />
                </Field>
              </div>
            </div>
          )}
        </FormSection>

        <FormSection title="Notifications">
          <Checkbox
            label="Email scan result changes and failures"
            description="Off by default. When on, mail New / Changed / Fixed after a completed scan, and failed or orphaned scans. Operator cancel stays silent."
            checked={notifyEnabled}
            onChange={setNotifyEnabled}
          />
          <Field
            label="Recipients"
            hint="Comma-separated. Empty uses the deployment SMTP_TO admin mailbox for digest and failure mail. With the flag off, no mail is sent."
            error={recipientsInvalid(notifyRecipients) && "Each recipient must be an email address."}
          >
            <Textarea
              rows={2}
              value={notifyRecipients}
              onChange={(e) => setNotifyRecipients(e.target.value)}
              placeholder="ops@example.com, sec@example.com"
              className="min-h-[2.5rem]"
            />
          </Field>
          <Field
            label="Minimum severity"
            hint="Applies to digest counts and the finding list. Unknown / non-standard severities are still included."
          >
            <Select
              value={notifyMinSeverity}
              onChange={(e) => setNotifyMinSeverity(e.target.value)}
              className="w-full sm:w-auto"
            >
              <option value="">All severities (including info)</option>
              <option value="low">Low and above (drop info)</option>
              <option value="medium">Medium and above</option>
              <option value="high">High and above</option>
              <option value="critical">Critical only</option>
            </Select>
          </Field>
        </FormSection>

        {anyInvalid && (
          <FormHint tone="danger">Each value must be a positive whole number (or blank to use the default).</FormHint>
        )}
        {save.isError && <ErrorText error={save.error} />}
        <ModalActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!canSave || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save scan policy"}
          </Button>
        </ModalActions>
      </div>
    </Modal>
  );
}

// executionSummary collapses the per-policy execution knobs into a short
// inline summary for the table. Only non-default (explicitly set) knobs are
// shown; an all-default policy renders as a muted "defaults" placeholder.
// The full set (including defaults) is available as a native tooltip.
function executionSummary(p: ScanPolicy): { label: string; title: string } {
  const parts: string[] = [];
  const tip: string[] = [];
  const push = (name: string, v: number | null | undefined, fmt?: (n: number) => string) => {
    tip.push(`${name}: ${v != null ? (fmt ? fmt(v) : String(v)) : `default`}`);
    if (v != null) parts.push(`${name} ${fmt ? fmt(v) : String(v)}`);
  };
  push("rate", p.rate_limit);
  push("concurrency", p.concurrency);
  push("timeout", p.timeout_sec, (n) => `${n}s`);
  push("max-host-error", p.max_host_error);
  push("resp-read", p.response_size_read, formatBytes);
  push("resp-save", p.response_size_save, formatBytes);
  const label = parts.length ? parts.join(" \u00b7 ") : "defaults";
  return { label, title: tip.join("\n") };
}

function formatBytes(n: number): string {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(n % (1 << 20) === 0 ? 0 : 1)} MiB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(n % (1 << 10) === 0 ? 0 : 1)} KiB`;
  return `${n} B`;
}

// discoverySummary builds the naabu pre-pass summary text for a policy.
function discoverySummary(p: ScanPolicy): string {
  if (p.discovery_enabled === false) return "off";
  const mode = p.discovery_scan_type?.trim() || "node default";
  const hostDiscovery =
    p.discovery_host_discovery == null
      ? "mode default"
      : p.discovery_host_discovery
        ? "host discovery"
        : "no host discovery";
  const ports = p.discovery_ports?.trim() || "top-1000";
  return `${mode} \u00b7 ${hostDiscovery} \u00b7 ${ports}`;
}

function notifySummary(p: ScanPolicy): string {
  if (!p.notify_enabled) return "off";
  const parts: string[] = ["on"];
  if (p.notify_min_severity) parts.push(`≥${p.notify_min_severity}`);
  const n = p.notify_recipients?.filter((r) => r.trim()).length ?? 0;
  if (n > 0) parts.push(`${n} recipient${n === 1 ? "" : "s"}`);
  return parts.join(" \u00b7 ");
}

export function ScanPoliciesPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [editing, setEditing] = useState<ScanPolicy | "new" | null>(null);
  const [duplicating, setDuplicating] = useState(false);

  const q = useQuery({ queryKey: ["scan-policies"], queryFn: () => api.listScanPolicies() });
  const templateSets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const templateSetName = (id?: string) =>
    id ? (templateSets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8)) : "missing";
  const del = useMutation({
    mutationFn: (id: string) => api.deleteScanPolicy(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["scan-policies"] }),
  });
  const openEditor = (policy: ScanPolicy | "new", duplicate = false) => {
    setDuplicating(duplicate);
    setEditing(policy);
  };
  const closeEditor = () => {
    setEditing(null);
    setDuplicating(false);
  };
  const showActions = canWrite || canDelete;

  return (
    <Page>
      <PageHeader
        title="Scan policies"
        description="Reusable template and execution settings. Choose the approved target when running or scheduling."
        actions={
          canWrite && (
            <Button variant="primary" onClick={() => openEditor("new")}>
              New scan policy
            </Button>
          )
        }
      />

      {del.isError && <ErrorText error={del.error} />}

      {q.isLoading ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : (
        <Card>
          <Table>
            <THead>
              <Th>Name</Th>
              <Th>Template set</Th>
              <Th>Execution</Th>
              <Th>Discovery</Th>
              <Th>Notify</Th>
              {showActions && <Th aria-label="Actions" />}
            </THead>
            <tbody>
              {(q.data ?? []).map((p) => {
                const exec = executionSummary(p);
                const disc = discoverySummary(p);
                return (
                  <TRow key={p.id}>
                    <Td className="font-medium">{p.name}</Td>
                    <Td className="text-neutral-600 dark:text-neutral-400">{templateSetName(p.template_set_id)}</Td>
                    <Td title={exec.title}>
                      {exec.label === "defaults" ? <Muted>defaults</Muted> : <span className="font-mono text-xs">{exec.label}</span>}
                    </Td>
                    <Td>{disc === "off" ? <Muted>off</Muted> : <span className="font-mono text-xs">{disc}</span>}</Td>
                    <Td>
                      {!p.notify_enabled ? <Muted>off</Muted> : <span className="font-mono text-xs">{notifySummary(p)}</span>}
                    </Td>
                    {showActions && (
                      <RowActions
                        label={p.name}
                        actions={[
                          { label: "Edit", primary: true, hidden: !canWrite, onSelect: () => openEditor(p) },
                          { label: "Duplicate", hidden: !canWrite, onSelect: () => openEditor(p, true) },
                          {
                            label: "Delete",
                            danger: true,
                            hidden: !canDelete,
                            onSelect: async () => {
                              if (
                                await confirm({
                                  title: `Delete scan policy “${p.name}”?`,
                                  description: "Schedules that use this policy are deleted with it. Past scans keep their history.",
                                  confirmLabel: "Delete policy",
                                })
                              )
                                del.mutate(p.id);
                            },
                          },
                        ]}
                      />
                    )}
                  </TRow>
                );
              })}
              {(q.data ?? []).length === 0 && (
                <TableEmpty colSpan={5 + (showActions ? 1 : 0)}>No scan policies yet.</TableEmpty>
              )}
            </tbody>
          </Table>
        </Card>
      )}

      {editing && (
        <ScanPolicyModal
          existing={editing === "new" ? undefined : editing}
          duplicate={duplicating}
          existingNames={(q.data ?? []).map((policy) => policy.name)}
          onClose={closeEditor}
        />
      )}
    </Page>
  );
}
