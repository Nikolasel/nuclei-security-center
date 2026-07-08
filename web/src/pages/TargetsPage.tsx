import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type Target } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Spinner } from "../components/ui";
import { parseList } from "../util";

function TargetModal({ existing, onClose }: { existing?: Target; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [hosts, setHosts] = useState((existing?.hosts ?? []).join("\n"));
  const [tags, setTags] = useState((existing?.tags ?? []).join(", "));

  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), hosts: parseList(hosts), tags: parseList(tags) };
      return existing ? api.updateTarget(existing.id, body) : api.createTarget(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["targets"] });
      onClose();
    },
  });

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title={existing ? "Edit target" : "New target"}>
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="prod-web" />
        </Field>
        <Field label="Hosts (one per line — the scope allowlist)">
          <textarea
            value={hosts}
            onChange={(e) => setHosts(e.target.value)}
            rows={4}
            placeholder="scanme.sh&#10;10.0.0.0/24&#10;https://example.com"
            className="w-full rounded-md border border-neutral-300 bg-white px-3 py-1.5 font-mono text-sm dark:border-neutral-700 dark:bg-neutral-800"
          />
        </Field>
        <Field label="Tags (comma separated)">
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="prod, external" />
        </Field>
        {save.isError && <ErrorText error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function TargetsPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Target | "new" | null>(null);

  const q = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteTarget(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["targets"] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Targets</h1>
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing("new")}>
            New target
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
                  <th className="px-3 py-2 font-medium">Hosts</th>
                  <th className="px-3 py-2 font-medium">Tags</th>
                  {(canWrite || canDelete) && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((t) => (
                  <tr key={t.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{t.name}</td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-600 dark:text-neutral-400">
                      {t.hosts.join(", ")}
                    </td>
                    <td className="px-3 py-2 text-neutral-500">{t.tags.join(", ") || "—"}</td>
                    {(canWrite || canDelete) && (
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        {canWrite && (
                          <Button variant="ghost" onClick={() => setEditing(t)}>
                            Edit
                          </Button>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            onClick={() => {
                              if (confirm(`Delete target "${t.name}"?`)) del.mutate(t.id);
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
                    <td colSpan={4} className="px-3 py-8 text-center text-neutral-400">
                      No targets yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <TargetModal existing={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}
