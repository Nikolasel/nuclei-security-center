import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Target } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Spinner } from "../components/ui";
import { duplicateName, parseList } from "../util";

function TargetModal({
  existing,
  duplicate = false,
  existingNames,
  onClose,
}: {
  existing?: Target;
  duplicate?: boolean;
  existingNames: string[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(
    existing ? (duplicate ? duplicateName(existing.name, existingNames) : existing.name) : "",
  );
  const [hosts, setHosts] = useState((existing?.hosts ?? []).join("\n"));
  const [tags, setTags] = useState((existing?.tags ?? []).join(", "));

  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), hosts: parseList(hosts), tags: parseList(tags) };
      return existing && !duplicate ? api.updateTarget(existing.id, body) : api.createTarget(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["targets"] });
      onClose();
    },
  });

  return (
    <Modal
      open
      onOpenChange={(v) => !v && onClose()}
      title={duplicate ? "Duplicate target" : existing ? "Edit target" : "New target"}
    >
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
  const [duplicating, setDuplicating] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedTargetID = searchParams.get("target") ?? "";

  const q = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const visibleTargets = selectedTargetID
    ? (q.data ?? []).filter((target) => target.id === selectedTargetID)
    : (q.data ?? []);
  const del = useMutation({
    mutationFn: (id: string) => api.deleteTarget(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["targets"] }),
  });
  const closeEditor = () => {
    setEditing(null);
    setDuplicating(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Targets</h1>
        {canWrite && (
          <Button
            variant="primary"
            onClick={() => {
              setDuplicating(false);
              setEditing("new");
            }}
          >
            New target
          </Button>
        )}
      </div>

      {selectedTargetID && (
        <div className="flex items-center justify-between rounded-md border border-indigo-200 bg-indigo-50 px-3 py-2 text-sm text-indigo-800 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-200">
          <span>Showing the linked target.</span>
          <Button variant="ghost" onClick={() => setSearchParams({})}>
            Show all
          </Button>
        </div>
      )}

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
                {visibleTargets.map((t) => (
                  <tr
                    key={t.id}
                    className={`border-b border-neutral-100 last:border-0 dark:border-neutral-800/60 ${
                      t.id === selectedTargetID ? "bg-indigo-50 dark:bg-indigo-950/30" : ""
                    }`}
                  >
                    <td className="px-3 py-2 font-medium">{t.name}</td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-600 dark:text-neutral-400">
                      {t.hosts.join(", ")}
                    </td>
                    <td className="px-3 py-2 text-neutral-500">{t.tags.join(", ") || "—"}</td>
                    {(canWrite || canDelete) && (
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        {canWrite && (
                          <Button
                            variant="ghost"
                            onClick={() => {
                              setDuplicating(false);
                              setEditing(t);
                            }}
                          >
                            Edit
                          </Button>
                        )}
                        {canWrite && (
                          <Button
                            variant="ghost"
                            onClick={() => {
                              setDuplicating(true);
                              setEditing(t);
                            }}
                          >
                            Duplicate
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
                {visibleTargets.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-3 py-8 text-center text-neutral-400">
                      {selectedTargetID ? "The linked target no longer exists." : "No targets yet."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <TargetModal
          existing={editing === "new" ? undefined : editing}
          duplicate={duplicating}
          existingNames={(q.data ?? []).map((target) => target.name)}
          onClose={closeEditor}
        />
      )}
    </div>
  );
}
