import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import {
  api,
  SEVERITIES,
  type SortOrder,
  type Template,
  type TemplateArchiveFormat,
  type TemplateDetail,
  type TemplateImportResponse,
  type TemplateSort,
  type TemplateSource,
  type TemplatesQuery,
} from "../api";
import { hasRole, useMe } from "../auth";
import { TemplateArchiveImportModal } from "../components/TemplateArchiveImportModal";
import {
  Button,
  Card,
  ErrorText,
  Field,
  Input,
  Modal,
  Pill,
  Select,
  SeverityBadge,
  Spinner,
  Textarea,
} from "../components/ui";
import { parseList } from "../util";

const PAGE_SIZE = 30;
// Stay below the common 8 KiB request-line ceiling used by proxies. For larger
// selections, a named set provides the path-based export endpoint.
const MAX_TEMPLATE_EXPORT_URL_LENGTH = 7_000;

function fmtTime(value?: string) {
  return value ? new Date(value).toLocaleString() : "—";
}

function shortDigest(value?: string) {
  return value ? value.slice(0, 12) : "—";
}

function TemplateDetailModal({
  templateID,
  onClose,
}: {
  templateID: string;
  onClose: () => void;
}) {
  const detail = useQuery({
    queryKey: ["template", templateID],
    queryFn: () => api.getTemplate(templateID),
  });
  return (
    <Modal
      open
      onOpenChange={(open) => !open && onClose()}
      title={detail.data?.name || templateID}
      size="wide"
    >
      {detail.isError ? (
        <ErrorText error={detail.error} />
      ) : detail.isLoading || !detail.data ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Template ID</dt>
              <dd className="mt-1 font-mono text-xs">{detail.data.id}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Source</dt>
              <dd className="mt-1">{detail.data.source}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Author</dt>
              <dd className="mt-1">{detail.data.author || "—"}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Revision</dt>
              <dd className="mt-1 tabular-nums">{detail.data.revision}</dd>
            </div>
          </dl>
          {detail.data.description && <p className="text-sm text-neutral-600 dark:text-neutral-400">{detail.data.description}</p>}
          <pre className="max-h-[50dvh] overflow-auto rounded-md bg-neutral-950 p-4 text-xs text-neutral-100">
            {detail.data.yaml}
          </pre>
          <div className="flex justify-end">
            <Button onClick={onClose}>Close</Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

const SAMPLE_TEMPLATE = `id: custom-example

info:
  name: Custom example
  author: security-team
  severity: info
  description: Replace this example with an organization-specific check.
  tags: custom

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`;

function CustomTemplateModal({
  existing,
  onClose,
  onSaved,
}: {
  existing?: Template;
  onClose: () => void;
  onSaved: (saved: TemplateDetail) => void;
}) {
  const qc = useQueryClient();
  const detail = useQuery({
    queryKey: ["template", existing?.id],
    queryFn: () => api.getTemplate(existing!.id),
    enabled: existing != null,
  });
  const [draft, setDraft] = useState(existing ? "" : SAMPLE_TEMPLATE);
  const [draftLoaded, setDraftLoaded] = useState(existing == null);
  useEffect(() => {
    if (!draftLoaded && detail.data) {
      setDraft(detail.data.yaml);
      setDraftLoaded(true);
    }
  }, [detail.data, draftLoaded]);
  const yaml = draft;
  const save = useMutation({
    mutationFn: () =>
      existing ? api.updateTemplate(existing.id, yaml) : api.createTemplate(yaml),
    onSuccess: (saved) => {
      qc.setQueryData<TemplateDetail>(["template", saved.id], saved);
      void qc.invalidateQueries({ queryKey: ["templates"] });
      onSaved(saved);
      onClose();
    },
  });

  return (
    <Modal
      open
      onOpenChange={(open) => !open && onClose()}
      title={existing ? `Edit ${existing.id}` : "New custom template"}
      size="wide"
    >
      {existing && detail.isLoading ? (
        <Spinner />
      ) : detail.isError ? (
        <ErrorText error={detail.error} />
      ) : (
        <div className="space-y-4">
          <p className="text-xs text-neutral-500">
            Upload or paste one Nuclei YAML document. A healthy scanner node validates it with the
            deployed Nuclei engine before it is saved. The template ID is immutable after creation.
          </p>
          <input
            type="file"
            accept=".yaml,.yml,application/yaml,text/yaml,text/plain"
            className="block w-full text-xs text-neutral-500 file:mr-3 file:rounded-md file:border-0 file:bg-neutral-100 file:px-3 file:py-1.5 file:text-sm file:font-medium dark:file:bg-neutral-800"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void file.text().then(setDraft);
            }}
          />
          <Field label="Template YAML">
            <Textarea
              rows={22}
              value={yaml}
              onChange={(event) => setDraft(event.target.value)}
              spellCheck={false}
              className="text-xs"
            />
          </Field>
          {save.isError && <ErrorText error={save.error} />}
          <div className="flex justify-end gap-2">
            <Button onClick={onClose}>Cancel</Button>
            <Button
              variant="primary"
              disabled={save.isPending || !yaml.trim() || (existing != null && detail.isLoading)}
              onClick={() => save.mutate()}
            >
              {save.isPending ? "Validating and saving…" : "Save template"}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

function CatalogTable({
  templates,
  selected,
  onToggle,
  onView,
  actions,
  sort,
  order,
  onSort,
}: {
  templates: Template[];
  selected?: Set<string>;
  onToggle?: (id: string) => void;
  onView: (template: Template) => void;
  actions?: (template: Template) => ReactNode;
  sort?: TemplateSort;
  order?: SortOrder;
  onSort?: (sort: TemplateSort) => void;
}) {
  const header = (label: string, value: TemplateSort) => (
    <th
      className="px-3 py-2 font-medium"
      aria-sort={sort === value ? (order === "desc" ? "descending" : "ascending") : "none"}
    >
      {onSort ? (
        <button
          type="button"
          className="inline-flex items-center gap-1 hover:text-indigo-600"
          onClick={() => onSort(value)}
        >
          {label}
          <span aria-hidden="true" className={sort === value ? "text-indigo-600" : "text-neutral-300"}>
            {sort === value ? (order === "desc" ? "↓" : "↑") : "↕"}
          </span>
        </button>
      ) : label}
    </th>
  );
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
            {selected && <th className="w-10 px-3 py-2" />}
            {header("Template", "name")}
            {header("Severity", "severity")}
            {header("Source", "source")}
            <th className="px-3 py-2 font-medium">Tags</th>
            {header("Inserted", "inserted")}
            {header("Revision", "revision")}
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {templates.map((template) => (
            <tr key={template.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
              {selected && (
                <td className="px-3 py-2">
                  <input
                    type="checkbox"
                    checked={selected.has(template.id)}
                    onChange={() => onToggle?.(template.id)}
                    aria-label={`Select ${template.id}`}
                  />
                </td>
              )}
              <td className="max-w-md px-3 py-2">
                <button type="button" className="text-left font-medium hover:text-indigo-600" onClick={() => onView(template)}>
                  {template.name || template.id}
                </button>
                <div className="mt-0.5 truncate font-mono text-xs text-neutral-500" title={template.id}>
                  {template.id}
                </div>
              </td>
              <td className="px-3 py-2"><SeverityBadge severity={template.severity} /></td>
              <td className="px-3 py-2">
                <Pill tone={template.source === "custom" ? "good" : "neutral"}>{template.source}</Pill>
              </td>
              <td className="max-w-xs px-3 py-2 text-xs text-neutral-500">
                <span className="line-clamp-2">{template.tags.join(", ") || "—"}</span>
              </td>
              <td className="whitespace-nowrap px-3 py-2 text-xs text-neutral-500">{fmtTime(template.created_at)}</td>
              <td className="px-3 py-2 tabular-nums text-neutral-500">{template.revision}</td>
              <td className="whitespace-nowrap px-3 py-2 text-right">
                <Button variant="ghost" onClick={() => onView(template)}>View YAML</Button>
                {actions?.(template)}
              </td>
            </tr>
          ))}
          {templates.length === 0 && (
            <tr>
              <td colSpan={selected ? 8 : 7} className="px-3 py-8 text-center text-neutral-400">
                No templates match these filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Pager({
  offset,
  total,
  onChange,
  pageSize = PAGE_SIZE,
}: {
  offset: number;
  total: number;
  onChange: (offset: number) => void;
  pageSize?: number;
}) {
  if (total <= pageSize) return null;
  return (
    <div className="flex items-center justify-between border-t border-neutral-200 px-3 py-2 text-xs text-neutral-500 dark:border-neutral-800">
      <span>
        {offset + 1}–{Math.min(offset + pageSize, total)} of {total}
      </span>
      <div className="flex gap-2">
        <Button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - pageSize))}>Previous</Button>
        <Button disabled={offset + pageSize >= total} onClick={() => onChange(offset + pageSize)}>Next</Button>
      </div>
    </div>
  );
}

function CatalogTab({ canWrite }: { canWrite: boolean }) {
  const qc = useQueryClient();
  const [source, setSource] = useState<TemplateSource | "">("");
  const [severity, setSeverity] = useState("");
  const [query, setQuery] = useState("");
  const [tags, setTags] = useState("");
  const [sort, setSort] = useState<TemplateSort>("name");
  const [order, setOrder] = useState<SortOrder>("asc");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [viewing, setViewing] = useState<Template | null>(null);
  const [setID, setSetID] = useState("");
  const [setName, setSetName] = useState("");
  const [notice, setNotice] = useState("");
  const [exportFormat, setExportFormat] = useState<TemplateArchiveFormat>("yaml");
  const filters: TemplatesQuery = {
    source: source || undefined,
    severities: severity ? [severity] : undefined,
    tags: parseList(tags),
    q: query.trim(),
    sort,
    order,
  };

  const templates = useQuery({
    queryKey: ["templates", "catalog", source, severity, query, tags, sort, order, offset],
    queryFn: () =>
      api.listTemplates({
        ...filters,
        limit: PAGE_SIZE,
        offset,
      }),
  });
  const sets = useQuery({ queryKey: ["template-sets"], queryFn: () => api.listTemplateSets() });
  const explicitSets = (sets.data ?? []).filter((set) => !set.dynamic_all);
  const add = useMutation({
    mutationFn: () => api.addTemplateSetMembers(setID, [...selected]),
    onSuccess: (set) => {
      setNotice(`Added ${selected.size} selected templates to "${set.name}".`);
      setSelected(new Set());
      void qc.invalidateQueries({ queryKey: ["template-sets"] });
    },
  });
  const create = useMutation({
    mutationFn: async () => {
      const set = await api.createTemplateSet({ name: setName.trim() });
      return api.replaceTemplateSetMembers(set.id, [...selected]);
    },
    onSuccess: (set) => {
      setNotice(`Created "${set.name}" with ${set.member_count} templates.`);
      setSelected(new Set());
      setSetName("");
      void qc.invalidateQueries({ queryKey: ["template-sets"] });
    },
  });
  const download = useMutation({
    mutationFn: () => api.downloadTemplates([...selected], exportFormat),
  });
  const selectMatching = useMutation({
    mutationFn: () => api.listTemplateIDs(filters),
    onSuccess: ({ ids }) => setSelected(new Set(ids)),
  });
  const resetPage = () => setOffset(0);
  const changeSort = (nextSort: TemplateSort) => {
    if (nextSort === sort) {
      setOrder((current) => current === "asc" ? "desc" : "asc");
    } else {
      setSort(nextSort);
      setOrder(["severity", "inserted", "revision"].includes(nextSort) ? "desc" : "asc");
    }
    resetPage();
  };
  const exportURL = api.templateExportURL([...selected], exportFormat);
  const exportTooLarge = exportURL.length > MAX_TEMPLATE_EXPORT_URL_LENGTH;

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <Field label="Search">
            <Input value={query} onChange={(event) => { setQuery(event.target.value); resetPage(); }} placeholder="ID, name, description" />
          </Field>
          <Field label="Source">
            <Select className="w-full" value={source} onChange={(event) => { setSource(event.target.value as TemplateSource | ""); resetPage(); }}>
              <option value="">All sources</option>
              <option value="upstream">Upstream</option>
              <option value="custom">Custom</option>
            </Select>
          </Field>
          <Field label="Severity">
            <Select className="w-full" value={severity} onChange={(event) => { setSeverity(event.target.value); resetPage(); }}>
              <option value="">All severities</option>
              {SEVERITIES.map((value) => <option key={value} value={value}>{value}</option>)}
            </Select>
          </Field>
          <Field label="Tags (comma separated)">
            <Input value={tags} onChange={(event) => { setTags(event.target.value); resetPage(); }} placeholder="cve, rce" />
          </Field>
        </div>
      </Card>

      {selected.size > 0 && (
        <Card className="p-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="mr-auto">
              <div className="font-medium">{selected.size} selected</div>
              <button type="button" className="text-xs text-indigo-600 hover:underline" onClick={() => setSelected(new Set())}>Clear selection</button>
            </div>
            <Field label="Export format">
              <Select value={exportFormat} onChange={(event) => setExportFormat(event.target.value as TemplateArchiveFormat)}>
                <option value="yaml">YAML archive (.tar.gz)</option>
                <option value="json">JSON document</option>
              </Select>
            </Field>
            <Button disabled={exportTooLarge || download.isPending} onClick={() => download.mutate()}>
              {download.isPending ? "Preparing export…" : "Export selected"}
            </Button>
            {canWrite && (
              <>
                <Field label="Add to existing set">
                  <Select className="min-w-52" value={setID} onChange={(event) => setSetID(event.target.value)}>
                    <option value="">Choose a set…</option>
                    {explicitSets.map((set) => <option key={set.id} value={set.id}>{set.name}</option>)}
                  </Select>
                </Field>
                <Button variant="primary" disabled={!setID || add.isPending} onClick={() => add.mutate()}>
                  {add.isPending ? "Adding…" : "Add selected"}
                </Button>
                <Field label="Or create a set">
                  <Input className="w-52" value={setName} onChange={(event) => setSetName(event.target.value)} placeholder="internet-exposure" />
                </Field>
                <Button variant="primary" disabled={!setName.trim() || create.isPending} onClick={() => create.mutate()}>
                  {create.isPending ? "Creating…" : "Create from selection"}
                </Button>
              </>
            )}
          </div>
          {exportTooLarge && (
            <p className="mt-3 text-xs text-amber-700 dark:text-amber-300">
              This selection is too large for a reliable URL-based export.{" "}
              {canWrite
                ? "Add it to a template set and export the set instead."
                : "Ask an operator to save it as a template set, then export the set."}
            </p>
          )}
          {download.isError && <div className="mt-3"><ErrorText error={download.error} /></div>}
          {(add.isError || create.isError) && <div className="mt-3"><ErrorText error={add.error ?? create.error} /></div>}
        </Card>
      )}
      {notice && <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">{notice}</div>}
      {selectMatching.isError && <ErrorText error={selectMatching.error} />}

      {templates.isError ? <ErrorText error={templates.error} /> : templates.isLoading || !templates.data ? <Spinner /> : (
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-neutral-200 px-3 py-2 text-xs text-neutral-500 dark:border-neutral-800">
            <span>{templates.data.total} templates match the current filters.</span>
            <div className="flex flex-wrap gap-2">
              <Button
                onClick={() => setSelected((current) => {
                  const next = new Set(current);
                  templates.data.items.forEach((template) => next.add(template.id));
                  return next;
                })}
              >
                Select this page
              </Button>
              <Button
                disabled={selectMatching.isPending || templates.data.total === 0}
                onClick={() => selectMatching.mutate()}
              >
                {selectMatching.isPending ? "Selecting…" : `Select all ${templates.data.total} matching`}
              </Button>
            </div>
          </div>
          <CatalogTable
            templates={templates.data.items}
            selected={selected}
            onToggle={(id) => setSelected((current) => {
              const next = new Set(current);
              if (next.has(id)) next.delete(id); else next.add(id);
              return next;
            })}
            onView={setViewing}
            sort={sort}
            order={order}
            onSort={changeSort}
          />
          <Pager offset={offset} total={templates.data.total} onChange={setOffset} />
        </Card>
      )}
      {viewing && <TemplateDetailModal templateID={viewing.id} onClose={() => setViewing(null)} />}
    </div>
  );
}

function CustomTab({ canWrite, canDelete }: { canWrite: boolean; canDelete: boolean }) {
  const qc = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [viewing, setViewing] = useState<Template | null>(null);
  const [editing, setEditing] = useState<Template | "new" | null>(null);
  const [notice, setNotice] = useState("");
  const [sort, setSort] = useState<TemplateSort>("name");
  const [order, setOrder] = useState<SortOrder>("asc");
  const templates = useQuery({
    queryKey: ["templates", "custom", sort, order, offset],
    queryFn: () => api.listTemplates({ source: "custom", sort, order, limit: PAGE_SIZE, offset }),
  });
  const changeSort = (nextSort: TemplateSort) => {
    if (nextSort === sort) {
      setOrder((current) => current === "asc" ? "desc" : "asc");
    } else {
      setSort(nextSort);
      setOrder(["severity", "inserted", "revision"].includes(nextSort) ? "desc" : "asc");
    }
    setOffset(0);
  };
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteTemplate(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["templates"] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-neutral-500">Organization-specific YAML, validated by Nuclei and stored losslessly alongside the upstream catalog.</p>
        {canWrite && <Button variant="primary" onClick={() => setEditing("new")}>New custom template</Button>}
      </div>
      {notice && <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">{notice}</div>}
      {remove.isError && <ErrorText error={remove.error} />}
      {templates.isError ? <ErrorText error={templates.error} /> : templates.isLoading || !templates.data ? <Spinner /> : (
        <Card>
          <CatalogTable
            templates={templates.data.items}
            onView={setViewing}
            sort={sort}
            order={order}
            onSort={changeSort}
            actions={(template) => (
              <>
                {canWrite && <Button variant="ghost" onClick={() => setEditing(template)}>Edit</Button>}
                {canDelete && (
                  <Button
                    variant="ghost"
                    className="text-red-600 dark:text-red-400"
                    onClick={() => {
                      if (confirm(`Delete custom template "${template.id}"?`)) remove.mutate(template.id);
                    }}
                  >
                    Delete
                  </Button>
                )}
              </>
            )}
          />
          <Pager offset={offset} total={templates.data.total} onChange={setOffset} />
        </Card>
      )}
      {viewing && <TemplateDetailModal templateID={viewing.id} onClose={() => setViewing(null)} />}
      {editing && (
        <CustomTemplateModal
          existing={editing === "new" ? undefined : editing}
          onClose={() => setEditing(null)}
          onSaved={(saved) => setNotice(
            `Saved ${saved.id}; validated with Nuclei ${saved.validation?.nuclei_version ?? "on the scanner node"}.`,
          )}
        />
      )}
    </div>
  );
}

function SyncTab({ canWrite }: { canWrite: boolean }) {
  const syncPageSize = 20;
  const qc = useQueryClient();
  const [offset, setOffset] = useState(0);
  const status = useQuery({ queryKey: ["template-sync"], queryFn: () => api.getTemplateSync() });
  const runs = useQuery({
    queryKey: ["template-sync-runs", offset],
    queryFn: () => api.listTemplateSyncRuns(syncPageSize, offset),
    refetchInterval: 15_000,
  });
  const trigger = useMutation({
    mutationFn: () => api.requestTemplateSync(),
    onSuccess: () => {
      setTimeout(() => void qc.invalidateQueries({ queryKey: ["template-sync-runs"] }), 1000);
    },
  });

  return (
    <div className="space-y-4">
      {status.isError ? <ErrorText error={status.error} /> : status.isLoading || !status.data ? <Spinner /> : (
        <Card className="p-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-semibold">Upstream mirror</h2>
                <Pill tone={status.data.enabled ? "good" : "warn"}>{status.data.enabled ? "enabled" : "disabled"}</Pill>
              </div>
              {status.data.enabled ? (
                <dl className="mt-3 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-3">
                  <div><dt className="text-xs text-neutral-500">Repository</dt><dd className="mt-0.5 break-all font-mono text-xs">{status.data.repo}</dd></div>
                  <div><dt className="text-xs text-neutral-500">Ref</dt><dd className="mt-0.5 font-mono text-xs">{status.data.ref}</dd></div>
                  <div><dt className="text-xs text-neutral-500">Interval</dt><dd className="mt-0.5">{status.data.interval}</dd></div>
                  <div>
                    <dt className="text-xs text-neutral-500">Active catalog bundle</dt>
                    <dd className="mt-0.5 font-mono text-xs" title={status.data.templates_commit}>
                      {shortDigest(status.data.templates_commit)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-neutral-500">Active templates</dt>
                    <dd className="mt-0.5 tabular-nums">{status.data.template_count}</dd>
                  </div>
                </dl>
              ) : (
                <p className="mt-2 text-sm text-neutral-500">Set TEMPLATE_SYNC_REPO to enable the community catalog mirror. Custom templates remain available.</p>
              )}
              <p className="mt-3 text-xs text-neutral-500">
                Configure the mirror on the backend with TEMPLATE_SYNC_REPO, TEMPLATE_SYNC_REF,
                and TEMPLATE_SYNC_INTERVAL. Changes take effect after a backend restart.
              </p>
            </div>
            {canWrite && (
              <Button variant="primary" disabled={!status.data.enabled || trigger.isPending} onClick={() => trigger.mutate()}>
                {trigger.isPending ? "Queueing…" : trigger.isSuccess ? "Sync queued" : "Sync now"}
              </Button>
            )}
          </div>
          {trigger.isError && <div className="mt-3"><ErrorText error={trigger.error} /></div>}
        </Card>
      )}

      {runs.isError ? <ErrorText error={runs.error} /> : runs.isLoading || !runs.data ? <Spinner /> : (
        <Card>
          <div className="border-b border-neutral-200 px-3 py-2 dark:border-neutral-800">
            <div className="font-medium">Sync history</div>
            <div className="text-xs text-neutral-500">
              {runs.data.total} retained {runs.data.total === 1 ? "run" : "runs"} in PostgreSQL.
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="px-3 py-2 font-medium">Started</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Result</th>
                  <th className="px-3 py-2 font-medium">Catalog bundle</th>
                  <th className="px-3 py-2 font-medium">Upstream commit</th>
                  <th className="px-3 py-2 font-medium">Finished</th>
                  <th className="px-3 py-2 font-medium">Error</th>
                </tr>
              </thead>
              <tbody>
                {runs.data.items.map((run) => (
                  <tr key={run.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 whitespace-nowrap">{fmtTime(run.started_at)}</td>
                    <td className="px-3 py-2"><Pill tone={run.status === "success" ? "good" : run.status === "failed" ? "warn" : "neutral"}>{run.status}</Pill></td>
                    <td className="px-3 py-2 whitespace-nowrap tabular-nums">+{run.added} / ~{run.updated} / −{run.removed} / {run.skipped} skipped</td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      {run.templates_commit ? (
                        <>
                          <div className="font-mono text-xs" title={run.templates_commit}>
                            {shortDigest(run.templates_commit)}
                          </div>
                          <div className="text-xs tabular-nums text-neutral-500">
                            {run.template_count ?? 0} templates
                          </div>
                        </>
                      ) : "—"}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs" title={run.ref_after}>{shortDigest(run.ref_after)}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-neutral-500">{fmtTime(run.finished_at)}</td>
                    <td className="max-w-md px-3 py-2 text-xs text-rose-600 dark:text-rose-400" title={run.error}>{run.error || "—"}</td>
                  </tr>
                ))}
                {runs.data.items.length === 0 && <tr><td colSpan={7} className="px-3 py-8 text-center text-neutral-400">No upstream sync has run yet.</td></tr>}
              </tbody>
            </table>
          </div>
          <Pager
            offset={offset}
            total={runs.data.total}
            pageSize={syncPageSize}
            onChange={setOffset}
          />
        </Card>
      )}
    </div>
  );
}

export function TemplatesPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const [searchParams, setSearchParams] = useSearchParams();
  const linkedTemplateID = searchParams.get("template");
  const [tab, setTab] = useState<"catalog" | "custom" | "sync">("catalog");
  const [importing, setImporting] = useState(false);
  const [importNotice, setImportNotice] = useState("");
  const qc = useQueryClient();

  const imported = (result: TemplateImportResponse) => {
    const summary = result.templates;
    const validation = result.validation
      ? ` Validated with Nuclei ${result.validation.nuclei_version}.`
      : " No custom writes required Nuclei validation.";
    setImportNotice(
      `Import complete: ${summary.created} created, ${summary.updated} updated, ${summary.skipped} skipped, ${summary.upstream_ignored} upstream ignored${summary.renamed.length ? `, ${summary.renamed.length} renamed` : ""}.${validation}`,
    );
    setImporting(false);
    void qc.invalidateQueries({ queryKey: ["templates"] });
    void qc.invalidateQueries({ queryKey: ["template-sets"] });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Templates</h1>
          <p className="mt-1 text-sm text-neutral-500">
            Browse the mirrored Nuclei catalog, author custom checks, and monitor catalog refreshes.
          </p>
        </div>
        {canWrite && <Button variant="primary" onClick={() => setImporting(true)}>Import templates</Button>}
      </div>
      {importNotice && <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">{importNotice}</div>}
      <div className="flex gap-1 border-b border-neutral-200 dark:border-neutral-800">
        {(["catalog", "custom", "sync"] as const).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => setTab(value)}
            className={`border-b-2 px-3 py-2 text-sm font-medium capitalize ${tab === value ? "border-indigo-600 text-indigo-700 dark:text-indigo-300" : "border-transparent text-neutral-500 hover:text-neutral-800 dark:hover:text-neutral-200"}`}
          >
            {value === "custom" ? "Custom templates" : value}
          </button>
        ))}
      </div>
      {tab === "catalog" && <CatalogTab canWrite={canWrite} />}
      {tab === "custom" && <CustomTab canWrite={canWrite} canDelete={canDelete} />}
      {tab === "sync" && <SyncTab canWrite={canWrite} />}
      {linkedTemplateID && (
        <TemplateDetailModal
          templateID={linkedTemplateID}
          onClose={() => {
            const next = new URLSearchParams(searchParams);
            next.delete("template");
            setSearchParams(next, { replace: true });
          }}
        />
      )}
      {importing && (
        <TemplateArchiveImportModal
          title="Import templates"
          description="Upload a template export in YAML archive or JSON format. This imports custom templates only; use Template Sets to restore a set and its membership."
          importArchive={api.importTemplates}
          onImported={imported}
          onClose={() => setImporting(false)}
        />
      )}
    </div>
  );
}
