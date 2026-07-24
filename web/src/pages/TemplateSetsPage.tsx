import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type TemplateSet } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Pill, Spinner } from "../components/ui";

function TemplateSetModal({ existing, onClose }: { existing?: TemplateSet; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const save = useMutation({
    mutationFn: () =>
      existing
        ? api.updateTemplateSet(existing.id, { name: name.trim() })
        : api.createTemplateSet({ name: name.trim() }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["template-sets"] });
      onClose();
    },
  });

  return (
    <Modal open onOpenChange={(open) => !open && onClose()} title={existing ? "Rename template set" : "New template set"}>
      <div className="space-y-4">
        <Field label="Name">
          <Input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="critical-cves"
            autoFocus
          />
        </Field>
        {!existing && (
          <p className="text-xs text-neutral-500">
            The new set starts empty. Add exact catalog template IDs through the membership API.
          </p>
        )}
        {save.isError && <ErrorText error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={save.isPending || !name.trim()}
            onClick={() => save.mutate()}
          >
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

function LegacySummary({ set }: { set: TemplateSet }) {
  const snapshot = set.legacy_filter_snapshot;
  if (!snapshot) return <span className="text-neutral-400">snapshot unavailable</span>;
  const parts = [
    snapshot.severities.length ? `severity: ${snapshot.severities.join(", ")}` : "",
    snapshot.tags.length ? `tags: ${snapshot.tags.join(", ")}` : "",
    snapshot.paths.length ? `paths: ${snapshot.paths.join(", ")}` : "",
    snapshot.git_ref ? `old ref: ${snapshot.git_ref}` : "",
  ].filter(Boolean);
  return <span title={parts.join(" · ")}>{parts.join(" · ") || "all templates"}</span>;
}

export function TemplateSetsPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [editing, setEditing] = useState<TemplateSet | "new" | null>(null);
  const [notice, setNotice] = useState("");

  const sets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteTemplateSet(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["template-sets"] }),
  });
  const convert = useMutation({
    mutationFn: (set: TemplateSet) => api.convertTemplateSet(set.id),
    onSuccess: (converted) => {
      setNotice(`Converted "${converted.name}" to ${converted.member_count} explicit template IDs.`);
      void qc.invalidateQueries({ queryKey: ["template-sets"] });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Template Sets</h1>
          <p className="mt-1 text-sm text-neutral-500">
            Sets now contain exact catalog template IDs. Legacy filter sets must be converted before use.
          </p>
        </div>
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing("new")}>
            New template set
          </Button>
        )}
      </div>

      {notice && (
        <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">
          {notice}
        </div>
      )}
      {remove.isError && <ErrorText error={remove.error} />}
      {convert.isError && <ErrorText error={convert.error} />}

      {sets.isLoading ? (
        <Spinner />
      ) : sets.isError ? (
        <ErrorText error={sets.error} />
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Mode</th>
                  <th className="px-3 py-2 font-medium">Members</th>
                  <th className="px-3 py-2 font-medium">Legacy snapshot</th>
                  {(canWrite || canDelete) && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(sets.data ?? []).map((set) => (
                  <tr key={set.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{set.name}</td>
                    <td className="px-3 py-2">
                      <Pill tone={set.legacy_filter ? "warn" : "good"}>
                        {set.legacy_filter ? "legacy filter" : "explicit"}
                      </Pill>
                    </td>
                    <td className="px-3 py-2 tabular-nums">
                      {set.legacy_filter ? "—" : set.member_count}
                    </td>
                    <td className="max-w-sm truncate px-3 py-2 text-xs text-neutral-500">
                      {set.legacy_filter ? <LegacySummary set={set} /> : "—"}
                    </td>
                    {(canWrite || canDelete) && (
                      <td className="whitespace-nowrap px-3 py-2 text-right">
                        {canWrite && set.legacy_filter && (
                          <Button
                            variant="primary"
                            disabled={convert.isPending && convert.variables?.id === set.id}
                            onClick={() => {
                              const confirmed = confirm(
                                `Convert "${set.name}" against the current active upstream catalog? ` +
                                  "This replaces its old filter with the exact IDs matched now.",
                              );
                              if (confirmed) {
                                setNotice("");
                                convert.mutate(set);
                              }
                            }}
                          >
                            {convert.isPending && convert.variables?.id === set.id
                              ? "Converting…"
                              : "Convert to selection"}
                          </Button>
                        )}
                        {canWrite && !set.legacy_filter && (
                          <Button variant="ghost" onClick={() => setEditing(set)}>
                            Rename
                          </Button>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            onClick={() => {
                              if (confirm(`Delete template set "${set.name}"?`)) {
                                remove.mutate(set.id);
                              }
                            }}
                          >
                            Delete
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
                {(sets.data ?? []).length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-3 py-8 text-center text-neutral-400">
                      No template sets yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <TemplateSetModal
          existing={editing === "new" ? undefined : editing}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}
