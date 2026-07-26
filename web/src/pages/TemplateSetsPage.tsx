import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  api,
  SEVERITIES,
  type TemplateArchiveFormat,
  type TemplateImportResponse,
  type TemplateSet,
  type TemplateSource,
} from "../api";
import { hasRole, useMe } from "../auth";
import { TemplateArchiveImportModal } from "../components/TemplateArchiveImportModal";
import { Button, Card, ErrorText, Field, Input, Modal, Pill, Select, SeverityBadge, Spinner } from "../components/ui";
import { parseList } from "../util";

const PAGE_SIZE = 20;

function TemplateSetModal({
  existing,
  readOnly = false,
  onClose,
}: {
  existing?: TemplateSet;
  readOnly?: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [query, setQuery] = useState("");
  const [source, setSource] = useState<TemplateSource | "">("");
  const [severity, setSeverity] = useState("");
  const [tags, setTags] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loadedMembers, setLoadedMembers] = useState(existing == null);

  const members = useQuery({
    queryKey: ["template-set-members", existing?.id],
    queryFn: () => api.listTemplateSetMembers(existing!.id),
    enabled: existing != null,
  });
  useEffect(() => {
    if (!loadedMembers && members.data) {
      setSelected(new Set(members.data.map((template) => template.id)));
      setLoadedMembers(true);
    }
  }, [loadedMembers, members.data]);

  const templates = useQuery({
    queryKey: ["templates", "set-picker", query, source, severity, tags, offset],
    queryFn: () =>
      api.listTemplates({
        q: query.trim(),
        source: source || undefined,
        severities: severity ? [severity] : undefined,
        tags: parseList(tags),
        limit: PAGE_SIZE,
        offset,
      }),
  });

  const save = useMutation({
    mutationFn: async () => {
      if (existing) {
        await api.updateTemplateSet(existing.id, { name: name.trim() });
        return api.replaceTemplateSetMembers(existing.id, [...selected]);
      }
      const created = await api.createTemplateSet({ name: name.trim() });
      return api.replaceTemplateSetMembers(created.id, [...selected]);
    },
    onSuccess: (saved) => {
      qc.setQueryData(["template-set-members", saved.id], undefined);
      void qc.invalidateQueries({ queryKey: ["template-sets"] });
      onClose();
    },
  });
  const resetPage = () => setOffset(0);
  const total = templates.data?.total ?? 0;

  return (
    <Modal
      open
      onOpenChange={(open) => !open && onClose()}
      title={existing ? `${readOnly ? "View" : "Edit"} ${existing.name}` : "New template set"}
      size="wide"
    >
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="critical-cves" autoFocus disabled={readOnly} />
        </Field>
        <div className="rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <h3 className="font-medium">Exact template selection</h3>
              <p className="text-xs text-neutral-500">The saved set records these immutable catalog IDs, not the filters below.</p>
            </div>
            <Pill tone={selected.size ? "good" : "warn"}>{selected.size} selected</Pill>
          </div>
          {selected.size === 0 && (
            <p className="mb-3 text-xs text-amber-700 dark:text-amber-300">
              Empty sets can be saved for later curation, but cannot be selected by a scan policy.
            </p>
          )}
          {selected.size > 0 && (
            <div className="mb-3 max-h-28 overflow-y-auto rounded-md bg-neutral-50 p-2 dark:bg-neutral-950/50">
              <div className="flex flex-wrap gap-1.5">
                {[...selected].sort().map((id) => (
                  <span key={id} className="inline-flex items-center gap-1 rounded border border-neutral-200 bg-white px-2 py-1 font-mono text-[11px] dark:border-neutral-700 dark:bg-neutral-900">
                    {id}
                    {!readOnly && (
                      <button
                        type="button"
                        className="text-neutral-400 hover:text-red-600"
                        aria-label={`Remove ${id}`}
                        onClick={() => setSelected((current) => {
                          const next = new Set(current);
                          next.delete(id);
                          return next;
                        })}
                      >
                        ×
                      </button>
                    )}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <Input value={query} onChange={(event) => { setQuery(event.target.value); resetPage(); }} placeholder="Search templates" aria-label="Search templates" />
            <Select value={source} onChange={(event) => { setSource(event.target.value as TemplateSource | ""); resetPage(); }} aria-label="Template source">
              <option value="">All sources</option>
              <option value="upstream">Upstream</option>
              <option value="custom">Custom</option>
            </Select>
            <Select value={severity} onChange={(event) => { setSeverity(event.target.value); resetPage(); }} aria-label="Template severity">
              <option value="">All severities</option>
              {SEVERITIES.map((value) => <option key={value} value={value}>{value}</option>)}
            </Select>
            <Input value={tags} onChange={(event) => { setTags(event.target.value); resetPage(); }} placeholder="Tags: cve, rce" aria-label="Template tags" />
          </div>

          {members.isLoading && existing ? <Spinner label="Loading current selection…" /> : templates.isError ? <ErrorText error={templates.error} /> : templates.isLoading || !templates.data ? <Spinner /> : (
            <>
              <div className="mt-3 max-h-72 overflow-y-auto rounded-md border border-neutral-200 dark:border-neutral-800">
                {templates.data.items.map((template) => (
                  <label key={template.id} className="flex cursor-pointer items-start gap-3 border-b border-neutral-100 px-3 py-2 last:border-0 hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-800/50">
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={selected.has(template.id)}
                      disabled={readOnly}
                      onChange={() => setSelected((current) => {
                        const next = new Set(current);
                        if (next.has(template.id)) next.delete(template.id); else next.add(template.id);
                        return next;
                      })}
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{template.name || template.id}</span>
                      <span className="block truncate font-mono text-xs text-neutral-500">{template.id}</span>
                    </span>
                    <SeverityBadge severity={template.severity} />
                    <Pill>{template.source}</Pill>
                  </label>
                ))}
                {templates.data.items.length === 0 && <div className="px-3 py-8 text-center text-sm text-neutral-400">No templates match these filters.</div>}
              </div>
              <div className="mt-2 flex items-center justify-between text-xs text-neutral-500">
                <span>{total ? `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${total}` : "0 templates"}</span>
                <div className="flex gap-2">
                  <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous</Button>
                  <Button disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</Button>
                </div>
              </div>
            </>
          )}
        </div>
        {members.isError && <ErrorText error={members.error} />}
        {save.isError && <ErrorText error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>{readOnly ? "Close" : "Cancel"}</Button>
          {!readOnly && (
            <Button
              variant="primary"
              disabled={save.isPending || !name.trim() || !loadedMembers}
              onClick={() => save.mutate()}
            >
              {save.isPending ? "Saving selection…" : `Save ${selected.size} templates`}
            </Button>
          )}
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
  const [importing, setImporting] = useState(false);
  const [exportFormat, setExportFormat] = useState<TemplateArchiveFormat>("yaml");

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
  const imported = (result: TemplateImportResponse) => {
    const summary = result.templates;
    const setResult = result.set
      ? ` Set "${result.set.name}" was ${result.set_status}.`
      : "";
    setNotice(
      `Import complete: ${summary.created} templates created, ${summary.updated} updated, ${summary.skipped} skipped, ${summary.upstream_ignored} upstream ignored.${setResult}`,
    );
    setImporting(false);
    void qc.invalidateQueries({ queryKey: ["templates"] });
    void qc.invalidateQueries({ queryKey: ["template-sets"] });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Template Sets</h1>
          <p className="mt-1 text-sm text-neutral-500">
            Curate exact template IDs for reproducible scans. Legacy filters must be converted before use.
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <Field label="Export format">
            <Select value={exportFormat} onChange={(event) => setExportFormat(event.target.value as TemplateArchiveFormat)}>
              <option value="yaml">YAML archive</option>
              <option value="json">JSON</option>
            </Select>
          </Field>
          {canWrite && <Button onClick={() => setImporting(true)}>Import set</Button>}
          {canWrite && <Button variant="primary" onClick={() => setEditing("new")}>New template set</Button>}
        </div>
      </div>

      {notice && <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">{notice}</div>}
      {remove.isError && <ErrorText error={remove.error} />}
      {convert.isError && <ErrorText error={convert.error} />}

      {sets.isLoading ? <Spinner /> : sets.isError ? <ErrorText error={sets.error} /> : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Mode</th>
                  <th className="px-3 py-2 font-medium">Members</th>
                  <th className="px-3 py-2 font-medium">Legacy snapshot</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {(sets.data ?? []).map((set) => (
                  <tr key={set.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{set.name}</td>
                    <td className="px-3 py-2"><Pill tone={set.legacy_filter ? "warn" : "good"}>{set.legacy_filter ? "legacy filter" : "explicit"}</Pill></td>
                    <td className="px-3 py-2 tabular-nums">{set.legacy_filter ? "—" : set.member_count}</td>
                    <td className="max-w-sm truncate px-3 py-2 text-xs text-neutral-500">{set.legacy_filter ? <LegacySummary set={set} /> : "—"}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                        {canWrite && set.legacy_filter && (
                          <Button
                            variant="primary"
                            disabled={convert.isPending && convert.variables?.id === set.id}
                            onClick={() => {
                              if (confirm(`Convert "${set.name}" against the current active upstream catalog? This freezes the exact IDs matched now.`)) {
                                setNotice("");
                                convert.mutate(set);
                              }
                            }}
                          >
                            {convert.isPending && convert.variables?.id === set.id ? "Converting…" : "Convert to selection"}
                          </Button>
                        )}
                        {!set.legacy_filter && (
                          <>
                            <Button
                              variant="ghost"
                              onClick={() => window.location.assign(api.templateSetExportURL(set.id, exportFormat))}
                            >
                              Export
                            </Button>
                            <Button variant="ghost" onClick={() => setEditing(set)}>
                              {canWrite ? "Edit selection" : "View selection"}
                            </Button>
                          </>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            onClick={() => {
                              if (confirm(`Delete template set "${set.name}"?`)) remove.mutate(set.id);
                            }}
                          >
                            Delete
                          </Button>
                        )}
                    </td>
                  </tr>
                ))}
                {(sets.data ?? []).length === 0 && <tr><td colSpan={5} className="px-3 py-8 text-center text-neutral-400">No template sets yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <TemplateSetModal
          existing={editing === "new" ? undefined : editing}
          readOnly={editing !== "new" && !canWrite}
          onClose={() => setEditing(null)}
        />
      )}
      {importing && (
        <TemplateArchiveImportModal
          title="Import template set"
          description="Upload a template-set export to restore its name, exact member IDs, and custom member YAML in one transaction."
          importArchive={api.importTemplateSet}
          onImported={imported}
          onClose={() => setImporting(false)}
        />
      )}
    </div>
  );
}
