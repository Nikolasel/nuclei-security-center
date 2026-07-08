import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type TemplateSet } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Spinner } from "../components/ui";
import { parseList } from "../util";

function TemplateSetModal({ existing, onClose }: { existing?: TemplateSet; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [gitRef, setGitRef] = useState(existing?.git_ref ?? "");
  const [severities, setSeverities] = useState((existing?.severities ?? []).join(", "));
  const [tags, setTags] = useState((existing?.tags ?? []).join(", "));
  const [paths, setPaths] = useState((existing?.paths ?? []).join("\n"));

  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: name.trim(),
        git_ref: gitRef.trim(),
        severities: parseList(severities),
        tags: parseList(tags),
        paths: parseList(paths),
      };
      return existing ? api.updateTemplateSet(existing.id, body) : api.createTemplateSet(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["template-sets"] });
      onClose();
    },
  });

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title={existing ? "Edit template set" : "New template set"}>
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="critical-cves" />
        </Field>
        <Field label="Severities (comma separated)">
          <Input
            value={severities}
            onChange={(e) => setSeverities(e.target.value)}
            placeholder="critical, high"
          />
        </Field>
        <Field label="Tags (comma separated)">
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="cve, rce" />
        </Field>
        <Field label="Paths (one per line, optional)">
          <textarea
            value={paths}
            onChange={(e) => setPaths(e.target.value)}
            rows={3}
            placeholder="http/cves/&#10;http/misconfiguration/"
            className="w-full rounded-md border border-neutral-300 bg-white px-3 py-1.5 font-mono text-sm dark:border-neutral-700 dark:bg-neutral-800"
          />
        </Field>
        <Field label="Pinned git ref (optional)">
          <Input value={gitRef} onChange={(e) => setGitRef(e.target.value)} placeholder="main" />
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

export function TemplateSetsPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [editing, setEditing] = useState<TemplateSet | "new" | null>(null);

  const q = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteTemplateSet(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["template-sets"] }),
  });

  const chips = (xs: string[]) =>
    xs.length ? (
      <div className="flex flex-wrap gap-1">
        {xs.map((x) => (
          <span key={x} className="rounded bg-neutral-100 px-1.5 py-0.5 text-xs dark:bg-neutral-800">
            {x}
          </span>
        ))}
      </div>
    ) : (
      <span className="text-neutral-400">—</span>
    );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Template Sets</h1>
        {canWrite && (
          <Button variant="primary" onClick={() => setEditing("new")}>
            New template set
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
                  <th className="px-3 py-2 font-medium">Severities</th>
                  <th className="px-3 py-2 font-medium">Tags</th>
                  <th className="px-3 py-2 font-medium">Git ref</th>
                  {(canWrite || canDelete) && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((t) => (
                  <tr key={t.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{t.name}</td>
                    <td className="px-3 py-2">{chips(t.severities)}</td>
                    <td className="px-3 py-2">{chips(t.tags)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-500">{t.git_ref || "—"}</td>
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
                              if (confirm(`Delete template set "${t.name}"?`)) del.mutate(t.id);
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
