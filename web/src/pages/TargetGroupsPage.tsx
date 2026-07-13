import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type TargetGroup } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Spinner } from "../components/ui";

function TargetGroupModal({ existing, onClose }: { existing?: TargetGroup; onClose: () => void }) {
  const qc = useQueryClient();
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const [name, setName] = useState(existing?.name ?? "");
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set((existing?.members ?? []).map((m) => m.id)),
  );

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), target_ids: [...selected] };
      return existing ? api.updateTargetGroup(existing.id, body) : api.createTargetGroup(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["target-groups"] });
      onClose();
    },
  });

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title={existing ? "Edit target group" : "New target group"}>
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="prod-external" />
        </Field>
        <Field label="Members">
          {targets.isLoading ? (
            <Spinner />
          ) : (
            <div className="max-h-56 space-y-1 overflow-y-auto rounded-md border border-neutral-300 p-2 dark:border-neutral-700">
              {(targets.data ?? []).map((t) => (
                <label key={t.id} className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={selected.has(t.id)} onChange={() => toggle(t.id)} />
                  <span>
                    {t.name}{" "}
                    <span className="text-neutral-400">
                      ({t.hosts.length} host{t.hosts.length === 1 ? "" : "s"})
                    </span>
                  </span>
                </label>
              ))}
              {(targets.data ?? []).length === 0 && (
                <p className="text-sm text-neutral-400">No targets yet — create one first.</p>
              )}
            </div>
          )}
        </Field>
        {save.isError && <ErrorText error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function TargetGroupsPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [editing, setEditing] = useState<TargetGroup | "new" | null>(null);

  const q = useQuery({ queryKey: ["target-groups"], queryFn: () => api.listTargetGroups() });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteTargetGroup(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["target-groups"] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Target Groups</h1>
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing("new")}>
            New group
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
                  <th className="px-3 py-2 font-medium">Members</th>
                  {(canWrite || canDelete) && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((g) => (
                  <tr key={g.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{g.name}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">
                      {g.members.length === 0
                        ? "—"
                        : g.members.map((m) => m.name).join(", ")}
                    </td>
                    {(canWrite || canDelete) && (
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        {canWrite && (
                          <Button variant="ghost" onClick={() => setEditing(g)}>
                            Edit
                          </Button>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            onClick={() => {
                              if (confirm(`Delete target group "${g.name}"?`)) del.mutate(g.id);
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
                    <td colSpan={3} className="px-3 py-8 text-center text-neutral-400">
                      No target groups yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <TargetGroupModal
          existing={editing === "new" ? undefined : editing}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}
