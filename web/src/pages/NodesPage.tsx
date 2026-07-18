import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type ScannerNode } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Pill, Spinner } from "../components/ui";
import { parseList } from "../util";

function fmtTime(s?: string) {
  return s ? new Date(s).toLocaleString() : "—";
}

/** HealthBadge renders a node's liveness (#98): green when healthy, red when a
 *  poll has failed past the TTL, neutral "unknown" until the first poll lands.
 *  When unhealthy, the poll failure (e.g. "401 Unauthorized" for a wrong token)
 *  is shown as subtext so an operator can tell *why* without reading server logs. */
function HealthBadge({ healthy, error }: { healthy?: boolean | null; error?: string }) {
  if (healthy == null) return <Pill tone="neutral">unknown</Pill>;
  if (healthy) return <Pill tone="good">healthy</Pill>;
  return (
    <div className="space-y-1">
      <Pill tone="warn">unhealthy</Pill>
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

  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: name.trim(),
        endpoint: endpoint.trim(),
        // Blank token on edit keeps the stored one; required on create.
        token: token.trim() || undefined,
        cidrs: parseList(cidrs),
        tags: parseList(tags),
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
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="corp" />
        </Field>
        <Field label="Endpoint (base URL the backend calls)">
          <Input
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="http://scanner-corp:8081"
          />
        </Field>
        <Field label={editing ? "Token (leave blank to keep current)" : "Token (bearer secret)"}>
          <Input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={editing ? "unchanged" : "shared scanner token"}
            autoComplete="new-password"
          />
        </Field>
        <Field label="CIDRs (one per line — empty = catch-all)">
          <textarea
            value={cidrs}
            onChange={(e) => setCidrs(e.target.value)}
            rows={3}
            placeholder="10.0.0.0/8&#10;192.168.1.0/24"
            className="w-full rounded-md border border-neutral-300 bg-white px-3 py-1.5 font-mono text-sm dark:border-neutral-700 dark:bg-neutral-800"
          />
        </Field>
        <p className="-mt-2 text-xs text-neutral-500">
          A node with no CIDRs is a catch-all for hostname targets and IPs matching no other node.
          CIDRs must not overlap another node.
        </p>
        <Field label="Tags (comma separated)">
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="corp, internal" />
        </Field>
        {save.isError && <ErrorText error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={save.isPending || !name.trim() || !endpoint.trim() || tokenMissing}
            onClick={() => save.mutate()}
          >
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function NodesPage() {
  const me = useMe();
  const isAdmin = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [editing, setEditing] = useState<ScannerNode | "new" | null>(null);

  const q = useQuery({ queryKey: ["nodes"], queryFn: () => api.listNodes() });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteNode(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["nodes"] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Scanner Nodes</h1>
          <p className="mt-1 text-sm text-neutral-500">
            The dispatch registry. A scan runs on the node whose CIDRs contain its target; nodes
            with no CIDRs are catch-alls. Health is polled from each node.
          </p>
        </div>
        {isAdmin && (
          <Button variant="primary" onClick={() => setEditing("new")}>
            New node
          </Button>
        )}
      </div>

      {del.isError && <ErrorText error={del.error} />}

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
                  <th className="px-3 py-2 font-medium">Health</th>
                  <th className="px-3 py-2 font-medium">Endpoint</th>
                  <th className="px-3 py-2 font-medium">CIDRs</th>
                  <th className="px-3 py-2 font-medium">Nuclei</th>
                  <th className="px-3 py-2 font-medium">Last seen</th>
                  <th className="px-3 py-2 font-medium">Tags</th>
                  {isAdmin && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((n) => (
                  <tr key={n.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{n.name}</td>
                    <td className="px-3 py-2">
                      <HealthBadge healthy={n.healthy} error={n.health_error} />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-600 dark:text-neutral-400">
                      {n.endpoint}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-600 dark:text-neutral-400">
                      {n.cidrs.length ? n.cidrs.join(", ") : <span className="text-neutral-400">catch-all</span>}
                    </td>
                    <td className="px-3 py-2 text-neutral-500">{n.nuclei_version || "—"}</td>
                    <td className="px-3 py-2 text-neutral-500">{fmtTime(n.last_seen)}</td>
                    <td className="px-3 py-2 text-neutral-500">{n.tags.join(", ") || "—"}</td>
                    {isAdmin && (
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        <Button variant="ghost" onClick={() => setEditing(n)}>
                          Edit
                        </Button>
                        <Button
                          variant="ghost"
                          className="text-red-600 dark:text-red-400"
                          onClick={() => {
                            if (confirm(`Delete scanner node "${n.name}"?`)) del.mutate(n.id);
                          }}
                        >
                          Delete
                        </Button>
                      </td>
                    )}
                  </tr>
                ))}
                {(q.data ?? []).length === 0 && (
                  <tr>
                    <td colSpan={isAdmin ? 8 : 7} className="px-3 py-8 text-center text-neutral-400">
                      No scanner nodes.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <NodeModal existing={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}
