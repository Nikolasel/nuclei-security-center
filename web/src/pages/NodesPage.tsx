import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type ScannerNode } from "../api";
import { hasRole, useMe } from "../auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  ErrorText,
  Field,
  FormSection,
  Input,
  Modal,
  ModalActions,
  Muted,
  Page,
  PageHeader,
  PropertyList,
  RowActions,
  type Property,
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
import { parseList } from "../util";

const defaultMaxConcurrentScans = 20;
const maxConcurrentScansCeiling = 100;

function fmtTime(s?: string) {
  return s ? new Date(s).toLocaleString() : "—";
}

/** discoveryProperty describes the node's effective naabu scan type (#271) as
 *  polled via /v1/capabilities. SYN is the default (needs CAP_NET_RAW +
 *  libpcap); connect is the unprivileged fallback. While the node has never been
 *  polled successfully the value is absent and renders as unknown rather than a
 *  guess — a per-scan policy can still override the node default. */
function discoveryProperty(scanType?: string): Property {
  const title = "Node default port-discovery mode — a policy's discovery_scan_type can override it per scan";
  if (scanType === "connect") return { label: "Connect discovery", title };
  if (scanType === "syn") return { label: "SYN discovery", title };
  return { label: "Discovery unknown", title: `${title}. Not reported until the node is polled successfully.` };
}

/** HealthBadge renders a node's liveness (#98): green when healthy, red when a
 *  poll has failed past the TTL, neutral "unknown" until the first poll lands.
 *  When unhealthy, the poll failure (e.g. "401 Unauthorized" for a wrong token)
 *  is shown as subtext so an operator can tell *why* without reading server logs. */
function HealthBadge({ healthy, error }: { healthy?: boolean | null; error?: string }) {
  if (healthy == null) return <Badge>unknown</Badge>;
  if (healthy) return <Badge tone="success">healthy</Badge>;
  return (
    <div className="space-y-1">
      <Badge tone="danger">unhealthy</Badge>
      {error && (
        <div className="max-w-xs text-xs text-rose-600 dark:text-rose-400" title={error}>
          {error}
        </div>
      )}
    </div>
  );
}

function NodeModal({ existing, onClose }: { existing?: ScannerNode; onClose: () => void }) {
  const qc = useQueryClient();
  const editing = existing != null;
  const [name, setName] = useState(existing?.name ?? "");
  const [endpoint, setEndpoint] = useState(existing?.endpoint ?? "");
  const [token, setToken] = useState("");
  const [cidrs, setCidrs] = useState((existing?.cidrs ?? []).join("\n"));
  const [tags, setTags] = useState((existing?.tags ?? []).join(", "));
  const [maxConcurrentScans, setMaxConcurrentScans] = useState(
    String(existing?.max_concurrent_scans ?? defaultMaxConcurrentScans),
  );
  // Per-node mTLS (#26). The server CA and client cert are public, so they are
  // returned and pre-filled; the client key is write-only, so it starts blank and
  // a blank value on edit keeps the stored key (like the token).
  const hasTLS = Boolean(existing?.tls_server_ca || existing?.tls_client_cert);
  const [showTLS, setShowTLS] = useState(hasTLS);
  const [serverCA, setServerCA] = useState(existing?.tls_server_ca ?? "");
  const [clientCert, setClientCert] = useState(existing?.tls_client_cert ?? "");
  const [clientKey, setClientKey] = useState("");

  const maxConcurrentScansNum = Number(maxConcurrentScans);
  const maxConcurrentScansValid =
    maxConcurrentScans.trim() !== "" &&
    Number.isInteger(maxConcurrentScansNum) &&
    maxConcurrentScansNum >= 1 &&
    maxConcurrentScansNum <= maxConcurrentScansCeiling;

  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: name.trim(),
        endpoint: endpoint.trim(),
        // Blank token on edit keeps the stored one; required on create.
        token: token.trim() || undefined,
        cidrs: parseList(cidrs),
        tags: parseList(tags),
        max_concurrent_scans: maxConcurrentScansNum,
        tls_server_ca: serverCA.trim(),
        tls_client_cert: clientCert.trim(),
        // Blank client key on edit keeps the stored one (write-only secret).
        tls_client_key: clientKey.trim() || undefined,
      };
      return editing ? api.updateNode(existing.id, body) : api.createNode(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["nodes"] });
      onClose();
    },
  });

  const tokenMissing = !editing && token.trim() === "";

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title={editing ? "Edit scanner node" : "New scanner node"}>
      <div className="space-y-4">
        <Field label="Name" required>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="corp" className="w-full" />
        </Field>
        <Field label="Endpoint" required hint="Base URL the backend calls.">
          <Input
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="http://scanner-corp:8081"
            className="w-full"
          />
        </Field>
        <Field
          label="Token"
          required={!editing}
          hint={editing ? "Leave blank to keep the current bearer secret." : "Bearer secret shared with the node."}
        >
          <Input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={editing ? "unchanged" : "shared scanner token"}
            autoComplete="new-password"
            className="w-full"
          />
        </Field>
        <Field
          label="CIDRs"
          hint="One per line. A node with no CIDRs is a catch-all for hostname targets and IPs matching no other node. CIDRs must not overlap another node."
        >
          <Textarea
            value={cidrs}
            onChange={(e) => setCidrs(e.target.value)}
            rows={3}
            placeholder="10.0.0.0/8&#10;192.168.1.0/24"
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label="Maximum concurrent scans"
            error={
              !maxConcurrentScansValid &&
              `Enter a whole number from 1 to ${maxConcurrentScansCeiling}. This limit protects this node's process, memory, and outbound scan budget.`
            }
          >
            <Input
              type="number"
              min={1}
              max={maxConcurrentScansCeiling}
              value={maxConcurrentScans}
              onChange={(e) => setMaxConcurrentScans(e.target.value)}
              className="w-full"
            />
          </Field>
          <Field label="Tags" hint="Comma separated.">
            <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="corp, internal" className="w-full" />
          </Field>
        </div>

        <FormSection>
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={showTLS}
            onClick={() => setShowTLS((v) => !v)}
            className="-ml-2.5"
          >
            {showTLS ? "−" : "+"} Mutual TLS (optional){hasTLS ? " · configured" : ""}
          </Button>
          {showTLS && (
            <div className="space-y-4">
              <p className="text-xs text-neutral-500">
                For a node in an untrusted segment: pin its server certificate and present a client
                certificate. Use an <code>https://</code> endpoint above. Paste PEM material. Leave
                empty for plain HTTP + bearer token.
              </p>
              <Field label="Server CA (PEM)" hint="Pins the node's server certificate.">
                <Textarea
                  value={serverCA}
                  onChange={(e) => setServerCA(e.target.value)}
                  rows={3}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  className="text-xs"
                />
              </Field>
              <Field label="Client certificate (PEM)" hint="Presented to the node.">
                <Textarea
                  value={clientCert}
                  onChange={(e) => setClientCert(e.target.value)}
                  rows={3}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  className="text-xs"
                />
              </Field>
              <Field
                label="Client private key (PEM)"
                hint={editing ? "Write-only. Leave blank to keep the current key." : "Write-only — never shown again."}
              >
                <Textarea
                  value={clientKey}
                  onChange={(e) => setClientKey(e.target.value)}
                  rows={3}
                  placeholder={editing && hasTLS ? "unchanged" : "-----BEGIN PRIVATE KEY-----"}
                  autoComplete="off"
                  className="text-xs"
                />
              </Field>
            </div>
          )}
        </FormSection>

        {save.isError && <ErrorText error={save.error} />}
        <ModalActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={save.isPending || !name.trim() || !endpoint.trim() || tokenMissing || !maxConcurrentScansValid}
            onClick={() => save.mutate()}
          >
            {save.isPending ? "Saving…" : "Save node"}
          </Button>
        </ModalActions>
      </div>
    </Modal>
  );
}

export function NodesPage() {
  const me = useMe();
  const isAdmin = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [editing, setEditing] = useState<ScannerNode | "new" | null>(null);
  const [notice, setNotice] = useState("");

  const q = useQuery({ queryKey: ["nodes"], queryFn: () => api.listNodes() });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteNode(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["nodes"] }),
  });
  const syncTemplates = useMutation({
    mutationFn: (node: ScannerNode) => api.syncNodeTemplates(node.id),
    onSuccess: (result, node) => {
      setNotice(
        `Pushed ${result.template_count} templates to "${node.name}" (${result.templates_commit.slice(0, 12)}).`,
      );
      void qc.invalidateQueries({ queryKey: ["nodes"] });
    },
  });

  return (
    <Page>
      <PageHeader
        title="Scanner nodes"
        description="The dispatch registry. A scan runs on the node whose CIDRs contain its target; nodes with no CIDRs are catch-alls. Health is polled from each node."
        actions={
          isAdmin && (
            <Button variant="primary" onClick={() => setEditing("new")}>
              New node
            </Button>
          )
        }
      />

      {notice && (
        <Alert tone="success" onDismiss={() => setNotice("")}>
          {notice}
        </Alert>
      )}
      {del.isError && <ErrorText error={del.error} />}
      {syncTemplates.isError && <ErrorText error={syncTemplates.error} />}

      {q.isLoading ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : (
        <Card>
          <Table>
            <THead>
              <Th>Name</Th>
              <Th>Status</Th>
              <Th>Properties</Th>
              <Th>Endpoint</Th>
              <Th>Scope</Th>
              <Th>Catalog</Th>
              {isAdmin && <Th aria-label="Actions" />}
            </THead>
            <tbody>
              {(q.data ?? []).map((n) => {
                const syncing = syncTemplates.isPending && syncTemplates.variables?.id === n.id;
                return (
                  <TRow key={n.id}>
                    <Td>
                      <div className="font-medium">{n.name}</div>
                      {n.tags.length > 0 && (
                        <div className="mt-0.5 max-w-[12rem] truncate text-xs text-neutral-500" title={n.tags.join(", ")}>
                          {n.tags.join(", ")}
                        </div>
                      )}
                    </Td>
                    <Td>
                      <HealthBadge healthy={n.healthy} error={n.health_error} />
                    </Td>
                    <Td>
                      <PropertyList
                        items={[
                          discoveryProperty(n.naabu_scan_type),
                          {
                            label: "mTLS",
                            title: "Mutual TLS configured: the node's server certificate is pinned and a client certificate is presented",
                            hidden: !(n.tls_client_cert || n.tls_server_ca),
                          },
                        ]}
                      />
                    </Td>
                    <Td className="max-w-[16rem] font-mono text-xs text-neutral-600 dark:text-neutral-400">
                      <span className="block truncate" title={n.endpoint}>
                        {n.endpoint}
                      </span>
                    </Td>
                    <Td className="text-xs">
                      <div
                        className="max-w-[12rem] truncate font-mono text-neutral-600 dark:text-neutral-400"
                        title={n.cidrs.length ? n.cidrs.join(", ") : "catch-all"}
                      >
                        {n.cidrs.length ? n.cidrs.join(", ") : <Muted>catch-all</Muted>}
                      </div>
                      <div className="mt-0.5 text-neutral-500">cap {n.max_concurrent_scans}</div>
                    </Td>
                    <Td className="text-xs text-neutral-500">
                      <div className="font-mono" title={n.templates_commit}>
                        {n.templates_commit ? n.templates_commit.slice(0, 12) : "none active"}
                        {n.nuclei_version ? ` · nuclei ${n.nuclei_version}` : ""}
                      </div>
                      <div className="mt-0.5" title={n.templates_synced_at ? new Date(n.templates_synced_at).toLocaleString() : undefined}>
                        pushed {fmtTime(n.templates_synced_at)}
                      </div>
                      <div className="mt-0.5" title={n.last_seen ? new Date(n.last_seen).toLocaleString() : undefined}>
                        seen {fmtTime(n.last_seen)}
                      </div>
                    </Td>
                    {isAdmin && (
                      <RowActions
                        label={n.name}
                        actions={[
                          { label: "Edit", primary: true, onSelect: () => setEditing(n) },
                          {
                            label: syncing ? "Syncing…" : "Sync templates",
                            title: "Push the active template catalog to this node now",
                            disabled: syncing,
                            onSelect: () => {
                              setNotice("");
                              syncTemplates.mutate(n);
                            },
                          },
                          {
                            label: "Delete",
                            danger: true,
                            onSelect: async () => {
                              if (
                                await confirm({
                                  title: `Delete scanner node “${n.name}”?`,
                                  description: "Scans can no longer be dispatched to it. Past scans keep their history.",
                                  confirmLabel: "Delete node",
                                })
                              )
                                del.mutate(n.id);
                            },
                          },
                        ]}
                      />
                    )}
                  </TRow>
                );
              })}
              {(q.data ?? []).length === 0 && <TableEmpty colSpan={isAdmin ? 7 : 6}>No scanner nodes.</TableEmpty>}
            </tbody>
          </Table>
        </Card>
      )}

      {editing && (
        <NodeModal existing={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />
      )}
    </Page>
  );
}
