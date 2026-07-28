import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  api,
  SEVERITIES,
  type TemplateArchiveFormat,
  type TemplateImportResponse,
  type TemplateSet,
  type TemplateSource,
  type TemplatesQuery,
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
  const [dynamicAll, setDynamicAll] = useState(existing?.dynamic_all ?? false);
  const [query, setQuery] = useState("");
  const [source, setSource] = useState<TemplateSource | "">("");
  const [severity, setSeverity] = useState("");
  const [tags, setTags] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loadedMembers, setLoadedMembers] = useState(existing == null || existing.dynamic_all);
  const filters: TemplatesQuery = {
    q: query.trim(),
    source: source || undefined,
    severities: severity ? [severity] : undefined,
    tags: parseList(tags),
  };

  const members = useQuery({
    queryKey: ["template-set-members", existing?.id],
    queryFn: () => api.listTemplateSetMembers(existing!.id),
    enabled: existing != null && !existing.dynamic_all,
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
        ...filters,
        limit: PAGE_SIZE,
        offset,
      }),
  });
  const selectMatching = useMutation({
    mutationFn: (mode: "select" | "deselect") =>
      api.listTemplateIDs(filters).then((result) => ({ ...result, mode })),
    onSuccess: ({ ids, mode }) => setSelected((current) => {
      const next = new Set(current);
      ids.forEach((id) => mode === "select" ? next.add(id) : next.delete(id));
      return next;
    }),
  });

  const save = useMutation({
    mutationFn: async () => {
      let saved: TemplateSet;
      if (existing) {
        saved = await api.updateTemplateSet(existing.id, {
          name: name.trim(),
          dynamic_all: dynamicAll,
        });
      } else {
        saved = await api.createTemplateSet({
          name: name.trim(),
          dynamic_all: dynamicAll,
        });
      }
      if (dynamicAll) return saved;
      return api.replaceTemplateSetMembers(saved.id, [...selected]);
    },
    onSuccess: (saved) => {
      qc.setQueryData(["template-set-members", saved.id], undefined);
      void qc.invalidateQueries({ queryKey: ["template-sets"] });
      onClose();
    },
  });
  const resetPage = () => setOffset(0);
  const total = templates.data?.total ?? 0;
  const selectedPreview = [...selected].sort().slice(0, 100);

  return (
    <Modal
      open
      onOpenChange={(open) => !open && onClose()}
      title={existing ? `${readOnly ? "View" : "Edit"} ${existing.name}` : "New template set"}
      size="workspace"
    >
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="critical-cves" autoFocus disabled={readOnly} />
        </Field>
        <Field label="Membership mode">
          <Select
            value={dynamicAll ? "dynamic" : "exact"}
            disabled={readOnly}
            onChange={(event) => setDynamicAll(event.target.value === "dynamic")}
            className="w-full"
          >
            <option value="exact">Exact selection</option>
            <option value="dynamic">All active templates (dynamic)</option>
          </Select>
        </Field>
        {dynamicAll ? (
          <div className="rounded-md border border-indigo-200 bg-indigo-50 p-3 text-sm text-indigo-800 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-300">
            This set always resolves to every active template at scan time. New templates from a
            later upstream sync are included automatically.
          </div>
        ) : (
          <div className="rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <h3 className="font-medium">Exact template selection</h3>
              <p className="text-xs text-neutral-500">The saved set records these immutable catalog IDs, not the filters below.</p>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-2">
              <Pill tone={selected.size ? "good" : "warn"}>{selected.size} selected</Pill>
              {!readOnly && (
                <>
                  <Button
                    disabled={selected.size === 0}
                    onClick={() => setSelected(new Set())}
                  >
                    Clear all
                  </Button>
                  <Button
                    disabled={!templates.data?.items.length}
                    onClick={() => setSelected((current) => {
                      const next = new Set(current);
                      templates.data?.items.forEach((template) => next.add(template.id));
                      return next;
                    })}
                  >
                    Select page
                  </Button>
                  <Button
                    disabled={!templates.data?.items.some((template) => selected.has(template.id))}
                    onClick={() => setSelected((current) => {
                      const next = new Set(current);
                      templates.data?.items.forEach((template) => next.delete(template.id));
                      return next;
                    })}
                  >
                    Deselect page
                  </Button>
                  <Button
                    disabled={selectMatching.isPending || total === 0}
                    onClick={() => selectMatching.mutate("select")}
                  >
                    {selectMatching.isPending ? "Selecting…" : `Select all ${total} matching`}
                  </Button>
                  <Button
                    disabled={selectMatching.isPending || total === 0 || selected.size === 0}
                    onClick={() => selectMatching.mutate("deselect")}
                  >
                    {selectMatching.isPending ? "Updating…" : `Deselect all ${total} matching`}
                  </Button>
                </>
              )}
            </div>
          </div>
          {selected.size === 0 && (
            <p className="mb-3 text-xs text-amber-700 dark:text-amber-300">
              Empty sets can be saved for later curation, but cannot be selected by a scan policy.
            </p>
          )}
          {selected.size > 0 && (
            <div className="mb-3 max-h-28 overflow-y-auto rounded-md bg-neutral-50 p-2 dark:bg-neutral-950/50">
              <div className="flex flex-wrap gap-1.5">
                {selectedPreview.map((id) => (
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
                {selected.size > selectedPreview.length && (
                  <span className="px-2 py-1 text-xs text-neutral-500">
                    +{selected.size - selectedPreview.length} more
                  </span>
                )}
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

          {selectMatching.isError && <ErrorText error={selectMatching.error} />}
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
        )}
        {members.isError && <ErrorText error={members.error} />}
        {save.isError && <ErrorText error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>{readOnly ? "Close" : "Cancel"}</Button>
          {!readOnly && (
            <Button
              variant="primary"
              disabled={save.isPending || !name.trim() || (!dynamicAll && !loadedMembers)}
              onClick={() => save.mutate()}
            >
              {save.isPending
                ? "Saving…"
                : dynamicAll
                  ? "Save dynamic set"
                  : `Save ${selected.size} templates`}
            </Button>
          )}
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
  const [notice, setNotice] = useState("");
  const [importing, setImporting] = useState(false);
  const [exportFormat, setExportFormat] = useState<TemplateArchiveFormat>("yaml");

  const sets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteTemplateSet(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["template-sets"] }),
  });
  const download = useMutation({
    mutationFn: ({ id }: { id: string }) => api.downloadTemplateSet(id, exportFormat),
  });
  const imported = (result: TemplateImportResponse) => {
    const summary = result.templates;
    const setResult = result.set
      ? ` Set "${result.set.name}" was ${result.set_status}.`
      : "";
    const validation = result.validation
      ? ` Validated with Nuclei ${result.validation.nuclei_version}.`
      : " No custom writes required Nuclei validation.";
    setNotice(
      `Import complete: ${summary.created} templates created, ${summary.updated} updated, ${summary.skipped} skipped, ${summary.upstream_ignored} upstream ignored.${setResult}${validation}`,
    );
    setImporting(false);
    void qc.invalidateQueries({ queryKey: ["templates"] });
    void qc.invalidateQueries({ queryKey: ["template-sets"] });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold">Template Sets</h1>
          <p className="mt-1 text-sm text-neutral-500">
            Curate exact template IDs, or explicitly choose a dynamic set containing every active template.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {canWrite && <Button onClick={() => setImporting(true)}>Import set</Button>}
          {canWrite && <Button variant="primary" onClick={() => setEditing("new")}>New template set</Button>}
        </div>
      </div>

      {notice && <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">{notice}</div>}
      {remove.isError && <ErrorText error={remove.error} />}
      {download.isError && <ErrorText error={download.error} />}

      {sets.isLoading ? <Spinner /> : sets.isError ? <ErrorText error={sets.error} /> : (
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-neutral-200 px-3 py-2 dark:border-neutral-800">
            <p className="text-xs text-neutral-500">
              Choose the format used by each row&apos;s Export action.
            </p>
            <label className="flex items-center gap-2 text-xs font-medium text-neutral-600 dark:text-neutral-400">
              <span>Export as</span>
              <Select
                className="min-w-32"
                value={exportFormat}
                onChange={(event) => setExportFormat(event.target.value as TemplateArchiveFormat)}
                aria-label="Template set export format"
              >
                <option value="yaml">YAML archive</option>
                <option value="json">JSON</option>
              </Select>
            </label>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Mode</th>
                  <th className="px-3 py-2 font-medium">Members</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {(sets.data ?? []).map((set) => (
                  <tr key={set.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{set.name}</td>
                    <td className="px-3 py-2"><Pill tone={set.dynamic_all ? "neutral" : "good"}>{set.dynamic_all ? "dynamic all" : "exact"}</Pill></td>
                    <td className="px-3 py-2 tabular-nums">
                      {set.member_count}{set.dynamic_all ? " active" : ""}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                        <Button
                          variant="ghost"
                          disabled={download.isPending}
                          onClick={() => download.mutate({ id: set.id })}
                        >
                          {download.isPending && download.variables?.id === set.id ? "Exporting…" : "Export"}
                        </Button>
                        <Button variant="ghost" onClick={() => setEditing(set)}>
                          {canWrite ? "Edit" : "View"}
                        </Button>
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
                {(sets.data ?? []).length === 0 && <tr><td colSpan={4} className="px-3 py-8 text-center text-neutral-400">No template sets yet.</td></tr>}
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
