import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  api,
  SEVERITIES,
  type TemplateArchiveFormat,
  type TemplateImportResponse,
  type TemplateSet,
  type TemplateSetMode,
  type TemplateSource,
  type TemplatesQuery,
} from "../api";
import { hasRole, useMe } from "../auth";
import { TemplateArchiveImportModal } from "../components/TemplateArchiveImportModal";
import {
  Alert,
  Button,
  Card,
  CardHeader,
  ErrorText,
  Field,
  FormHint,
  Input,
  Modal,
  ModalActions,
  Page,
  PageHeader,
  Pager,
  Pill,
  RowActions,
  Select,
  SeverityBadge,
  Spinner,
  Table,
  TableEmpty,
  Td,
  Th,
  THead,
  TRow,
  useConfirm,
  focusRing,
  cn,
} from "../components/ui";
import { duplicateName, parseList } from "../util";

const PAGE_SIZE = 20;

function TemplateSetModal({
  existing,
  duplicate = false,
  existingNames,
  readOnly = false,
  onClose,
}: {
  existing?: TemplateSet;
  duplicate?: boolean;
  existingNames: string[];
  readOnly?: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(
    existing ? (duplicate ? duplicateName(existing.name, existingNames) : existing.name) : "",
  );
  const [mode, setMode] = useState<TemplateSetMode>(existing?.mode ?? "exact");
  const [query, setQuery] = useState("");
  const [source, setSource] = useState<TemplateSource | "">("");
  const [severity, setSeverity] = useState("");
  const [tags, setTags] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const shouldLoadMembers = existing?.mode === "exact";
  const shouldLoadExclusions = existing?.mode === "exclude";
  const [loadedMembers, setLoadedMembers] = useState(!shouldLoadMembers);
  const [loadedExclusions, setLoadedExclusions] = useState(!shouldLoadExclusions);
  const filters: TemplatesQuery = {
    q: query.trim(),
    source: source || undefined,
    severities: severity ? [severity] : undefined,
    tags: parseList(tags),
  };

  const members = useQuery({
    queryKey: ["template-set-members", existing?.id],
    queryFn: () => api.listTemplateSetMembers(existing!.id),
    enabled: shouldLoadMembers && !loadedMembers,
  });
  useEffect(() => {
    if (!loadedMembers && members.data) {
      // Currently unreachable while the selection is hydrating (buttons and
      // checkboxes are gated), but merge instead of overwrite to stay safe
      // if a future change exposes a mutation path before the fetch lands.
      setSelected((prev) => {
        if (prev.size === 0) return new Set(members.data!.map((template) => template.id));
        const next = new Set(prev);
        members.data!.forEach((template) => next.add(template.id));
        return next;
      });
      setLoadedMembers(true);
    }
  }, [loadedMembers, members.data]);

  const exclusions = useQuery({
    queryKey: ["template-set-exclusions", existing?.id],
    queryFn: () => api.listTemplateSetExclusions(existing!.id),
    enabled: shouldLoadExclusions && !loadedExclusions,
  });
  useEffect(() => {
    if (!loadedExclusions && exclusions.data) {
      // See members hydration above — defense-in-depth against an
      // ungated mutation arriving before this fetch completes.
      setExcluded((prev) => {
        if (prev.size === 0) return new Set(exclusions.data!.map((template) => template.id));
        const next = new Set(prev);
        exclusions.data!.forEach((template) => next.add(template.id));
        return next;
      });
      setLoadedExclusions(true);
    }
  }, [exclusions.data, loadedExclusions]);

  useEffect(() => {
    if (existing == null || existing.mode !== mode) {
      if (mode === "exact") setLoadedMembers(true);
      if (mode === "exclude") setLoadedExclusions(true);
    }
  }, [existing?.mode, mode]);

  const templates = useQuery({
    queryKey: ["templates", "set-picker", query, source, severity, tags, offset],
    queryFn: () =>
      api.listTemplates({
        ...filters,
        limit: PAGE_SIZE,
        offset,
      }),
  });
  const selection = mode === "exclude" ? excluded : selected;
  const selectionHydrating =
    mode === "exact" ? !loadedMembers : mode === "exclude" ? !loadedExclusions : false;
  const updateSelection = (change: (next: Set<string>) => void) => {
    const update = (current: Set<string>) => {
      const next = new Set(current);
      change(next);
      return next;
    };
    if (mode === "exclude") setExcluded(update);
    else setSelected(update);
  };
  const selectMatching = useMutation({
    mutationFn: (mode: "select" | "deselect") =>
      api.listTemplateIDs(filters).then((result) => ({ ...result, mode })),
    onSuccess: ({ ids, mode }) => updateSelection((next) => {
      ids.forEach((id) => mode === "select" ? next.add(id) : next.delete(id));
    }),
  });

  const save = useMutation({
    mutationFn: async () => {
      let saved: TemplateSet;
      if (existing && !duplicate) {
        saved = await api.updateTemplateSet(existing.id, {
          name: name.trim(),
          mode,
          ...(mode === "exclude" ? { excluded_template_ids: [...excluded] } : {}),
        });
      } else {
        saved = await api.createTemplateSet({
          name: name.trim(),
          mode,
          ...(mode === "exclude" ? { excluded_template_ids: [...excluded] } : {}),
        });
      }
      if (mode !== "exact") return saved;
      return api.replaceTemplateSetMembers(saved.id, [...selected]);
    },
    onSuccess: (saved) => {
      qc.removeQueries({ queryKey: ["template-set-members", saved.id] });
      qc.removeQueries({ queryKey: ["template-set-exclusions", saved.id] });
      void qc.invalidateQueries({ queryKey: ["template-sets"] });
      onClose();
    },
  });
  const resetPage = () => setOffset(0);
  const total = templates.data?.total ?? 0;
  const selectedPreview = [...selection].sort().slice(0, 100);

  return (
    <Modal
      open
      onOpenChange={(open) => !open && onClose()}
      title={duplicate ? "Duplicate template set" : existing ? `${readOnly ? "View" : "Edit"} ${existing.name}` : "New template set"}
      size="workspace"
    >
      <div className="flex h-full min-h-0 flex-col">
        <div className="grid shrink-0 gap-4 px-5 py-4 md:grid-cols-2">
          <Field label="Name">
            <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="critical-cves" autoFocus disabled={readOnly} className="w-full" />
          </Field>
          <Field label="Membership mode">
            <Select
              value={mode}
              disabled={readOnly}
              onChange={(event) => setMode(event.target.value as TemplateSetMode)}
              className="w-full"
            >
              <option value="exact">Exact selection</option>
              <option value="all">All active templates</option>
              <option value="exclude">All active except selected exclusions</option>
            </Select>
          </Field>
        </div>
        <div className="mx-5 mb-4 flex min-h-0 flex-1 flex-col rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
          <div className="mb-3 flex shrink-0 items-center justify-between gap-3">
            <div>
              <h3 className="font-medium">
                {mode === "exact" ? "Exact template selection" : mode === "exclude" ? "Template exclusions" : "All active templates"}
              </h3>
              <p className="text-xs text-neutral-500">
                {mode === "exact"
                  ? "The saved set records these immutable catalog IDs, not the filters below."
                  : mode === "exclude"
                    ? "Every active template is included at scan time except checked exclusions. New active templates are included automatically."
                    : "Every active catalog template is included at scan time. New active templates are included automatically."}
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-2">
              {mode === "all" ? <Pill tone="good">all active</Pill> : <Pill tone={selection.size ? "good" : "warn"}>
                {selection.size} {mode === "exclude" ? "excluded" : "selected"}
              </Pill>}
              {!readOnly && mode !== "all" && (
                <>
                  <Button
                    size="sm"
                    disabled={selection.size === 0 || selectionHydrating}
                    onClick={() => updateSelection((next) => next.clear())}
                  >
                    Clear all
                  </Button>
                  <Button
                    size="sm"
                    disabled={!templates.data?.items.length || selectionHydrating}
                    onClick={() => updateSelection((next) => {
                      templates.data?.items.forEach((template) => next.add(template.id));
                    })}
                  >
                    {mode === "exclude" ? "Exclude page" : "Select page"}
                  </Button>
                  <Button
                    size="sm"
                    disabled={!templates.data?.items.some((template) => selection.has(template.id)) || selectionHydrating}
                    onClick={() => updateSelection((next) => {
                      templates.data?.items.forEach((template) => next.delete(template.id));
                    })}
                  >
                    {mode === "exclude" ? "Remove page exclusions" : "Deselect page"}
                  </Button>
                  <Button
                    size="sm"
                    disabled={selectMatching.isPending || total === 0 || selectionHydrating}
                    onClick={() => selectMatching.mutate("select")}
                  >
                    {selectMatching.isPending
                      ? mode === "exclude" ? "Excluding…" : "Selecting…"
                      : mode === "exclude" ? `Exclude all ${total} matching` : `Select all ${total} matching`}
                  </Button>
                  <Button
                    size="sm"
                    disabled={selectMatching.isPending || total === 0 || selection.size === 0 || selectionHydrating}
                    onClick={() => selectMatching.mutate("deselect")}
                  >
                    {selectMatching.isPending
                      ? "Updating…"
                      : mode === "exclude" ? `Remove ${total} exclusions` : `Deselect all ${total} matching`}
                  </Button>
                </>
              )}
            </div>
          </div>
          {mode !== "all" && (
            <div className="flex min-h-0 flex-1 flex-col">
              {selection.size === 0 && (
                <div className="mb-3">
                  <FormHint tone="warning">
                    {mode === "exclude"
                      ? "No exclusions: every active catalog template will be included."
                      : "Empty sets can be saved for later curation, but cannot be selected by a scan policy."}
                  </FormHint>
                </div>
              )}
          {selection.size > 0 && (
            <div className="mb-3 h-20 shrink-0 overflow-y-auto rounded-md bg-neutral-50 p-2 dark:bg-neutral-950/50">
              <div className="flex flex-wrap gap-1.5">
                {selectedPreview.map((id) => (
                  <span key={id} className="inline-flex items-center gap-1 rounded border border-neutral-200 bg-white px-2 py-1 font-mono text-[11px] dark:border-neutral-700 dark:bg-neutral-900">
                    {id}
                    {!readOnly && (
                      <button
                        type="button"
                        className={cn("rounded-sm text-neutral-400 hover:text-red-600", focusRing)}
                        aria-label={`${mode === "exclude" ? "Remove exclusion" : "Remove"} ${id}`}
                        onClick={() => updateSelection((next) => next.delete(id))}
                      >
                        ×
                      </button>
                    )}
                  </span>
                ))}
                {selection.size > selectedPreview.length && (
                  <span className="px-2 py-1 text-xs text-neutral-500">
                    +{selection.size - selectedPreview.length} more
                  </span>
                )}
              </div>
            </div>
          )}
          <div className="grid shrink-0 gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <Input className="w-full" value={query} onChange={(event) => { setQuery(event.target.value); resetPage(); }} placeholder="Search templates" aria-label="Search templates" />
            <Select value={source} onChange={(event) => { setSource(event.target.value as TemplateSource | ""); resetPage(); }} aria-label="Template source">
              <option value="">All sources</option>
              <option value="upstream">Upstream</option>
              <option value="custom">Custom</option>
            </Select>
            <Select value={severity} onChange={(event) => { setSeverity(event.target.value); resetPage(); }} aria-label="Template severity">
              <option value="">All severities</option>
              {SEVERITIES.map((value) => <option key={value} value={value}>{value}</option>)}
            </Select>
            <Input className="w-full" value={tags} onChange={(event) => { setTags(event.target.value); resetPage(); }} placeholder="Tags: cve, rce" aria-label="Template tags" />
          </div>

          {selectMatching.isError && <ErrorText error={selectMatching.error} />}
          <div className="mt-3 flex min-h-0 flex-1 flex-col">
          {(mode === "exclude" ? exclusions.isLoading : members.isLoading) && selectionHydrating ? <Spinner label="Loading current selection…" /> : templates.isError ? <ErrorText error={templates.error} /> : templates.isLoading || !templates.data ? <Spinner /> : (
            <>
              <div className="min-h-0 flex-1 overflow-y-auto rounded-md border border-neutral-200 dark:border-neutral-800">
                {templates.data.items.map((template) => (
                  <label key={template.id} className="flex cursor-pointer items-start gap-3 border-b border-neutral-100 px-3 py-2 last:border-0 hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-800/50">
                    <input
                      type="checkbox"
                      className="mt-1 h-4 w-4 accent-indigo-600"
                      checked={selection.has(template.id)}
                      disabled={readOnly}
                      onChange={() => updateSelection((next) => {
                        if (next.has(template.id)) next.delete(template.id); else next.add(template.id);
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
              <Pager
                className="mt-2 shrink-0"
                summary={total ? `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${total}` : "0 templates"}
                hasPrev={offset > 0}
                hasNext={offset + PAGE_SIZE < total}
                onPrev={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                onNext={() => setOffset(offset + PAGE_SIZE)}
              />
            </>
          )}
          </div>
          </div>
          )}
        {mode === "all" && (
          <div className="flex min-h-0 flex-1 items-center justify-center rounded-md bg-neutral-50 p-6 text-center text-sm text-neutral-500 dark:bg-neutral-950/50">
            This set has no stored membership. It resolves to every active catalog template when a scan starts.
          </div>
        )}
        </div>
        <div className="shrink-0 space-y-3 border-t border-neutral-200 px-5 py-3 dark:border-neutral-800">
          {members.isError && <ErrorText error={members.error} />}
          {exclusions.isError && <ErrorText error={exclusions.error} />}
          {save.isError && <ErrorText error={save.error} />}
          <ModalActions>
            <Button onClick={onClose}>{readOnly ? "Close" : "Cancel"}</Button>
            {!readOnly && (
              <Button
                variant="primary"
                disabled={save.isPending || !name.trim() || selectionHydrating}
                onClick={() => save.mutate()}
              >
                {save.isPending
                  ? "Saving…"
                  : mode === "all"
                    ? "Save all-active set"
                    : mode === "exclude"
                      ? "Save exclusions"
                      : `Save ${selection.size} templates`}
              </Button>
            )}
          </ModalActions>
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
  const confirm = useConfirm();
  const [editing, setEditing] = useState<TemplateSet | "new" | null>(null);
  const [duplicating, setDuplicating] = useState(false);
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
  const closeEditor = () => {
    setEditing(null);
    setDuplicating(false);
  };
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

  const openEditor = (set: TemplateSet | "new", duplicate = false) => {
    setDuplicating(duplicate);
    setEditing(set);
  };

  return (
    <Page>
      <PageHeader
        title="Template sets"
        description="Curate exact template IDs, include every active template, or exclude selected IDs while following the active catalog."
        actions={
          canWrite && (
            <>
              <Button onClick={() => setImporting(true)}>Import set</Button>
              <Button variant="primary" onClick={() => openEditor("new")}>
                New template set
              </Button>
            </>
          )
        }
      />

      {notice && (
        <Alert tone="success" onDismiss={() => setNotice("")}>
          {notice}
        </Alert>
      )}
      {remove.isError && <ErrorText error={remove.error} />}
      {download.isError && <ErrorText error={download.error} />}

      {sets.isLoading ? (
        <Spinner />
      ) : sets.isError ? (
        <ErrorText error={sets.error} />
      ) : (
        <Card>
          <CardHeader>
            <p className="text-xs text-neutral-500">Choose the format used by each row&apos;s Export action.</p>
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
          </CardHeader>
          <Table>
            <THead>
              <Th>Name</Th>
              <Th>Mode</Th>
              <Th>Members</Th>
              <Th aria-label="Actions" />
            </THead>
            <tbody>
              {(sets.data ?? []).map((set) => (
                <TRow key={set.id}>
                  <Td className="font-medium">{set.name}</Td>
                  <Td>
                    <Pill tone={set.mode === "exact" ? "good" : "neutral"}>{set.mode}</Pill>
                  </Td>
                  <Td className="tabular-nums">
                    <div>
                      {set.member_count}
                      {set.mode !== "exact" ? " active" : ""}
                    </div>
                    {set.mode === "exclude" && set.exclusion_count > 0 && (
                      <div className="text-xs text-amber-700 dark:text-amber-300">{set.exclusion_count} excluded</div>
                    )}
                  </Td>
                  <RowActions
                    label={set.name}
                    actions={[
                      { label: canWrite ? "Edit" : "View", primary: true, onSelect: () => openEditor(set) },
                      {
                        label: download.isPending && download.variables?.id === set.id ? "Exporting…" : "Export",
                        primary: true,
                        disabled: download.isPending,
                        onSelect: () => download.mutate({ id: set.id }),
                      },
                      { label: "Duplicate", hidden: !canWrite, onSelect: () => openEditor(set, true) },
                      {
                        label: "Delete",
                        danger: true,
                        hidden: !canDelete,
                        onSelect: async () => {
                          if (
                            await confirm({
                              title: `Delete template set “${set.name}”?`,
                              description: "Deletion is refused while a scan policy still uses this set.",
                              confirmLabel: "Delete set",
                            })
                          )
                            remove.mutate(set.id);
                        },
                      },
                    ]}
                  />
                </TRow>
              ))}
              {(sets.data ?? []).length === 0 && <TableEmpty colSpan={4}>No template sets yet.</TableEmpty>}
            </tbody>
          </Table>
        </Card>
      )}

      {editing && (
        <TemplateSetModal
          existing={editing === "new" ? undefined : editing}
          duplicate={duplicating}
          existingNames={(sets.data ?? []).map((set) => set.name)}
          readOnly={!duplicating && editing !== "new" && !canWrite}
          onClose={closeEditor}
        />
      )}
      {importing && (
        <TemplateArchiveImportModal
          title="Import template set"
          description="Upload a template-set export to restore its mode, exact members or exclusions, and custom YAML in one transaction."
          importArchive={api.importTemplateSet}
          onImported={imported}
          onClose={() => setImporting(false)}
        />
      )}
    </Page>
  );
}
