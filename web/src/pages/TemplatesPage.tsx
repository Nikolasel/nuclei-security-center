import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Fragment, useEffect, useState, type ReactNode } from "react";
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
  type TemplateSyncRun,
  type TemplatesQuery,
} from "../api";
import { hasRole, useMe } from "../auth";
import { TemplateArchiveImportModal } from "../components/TemplateArchiveImportModal";
import {
  Alert,
  Button,
  Card,
  CardHeader,
  DescriptionList,
  ErrorText,
  Field,
  FileInput,
  FormHint,
  focusRing,
  cn,
  Input,
  Meta,
  Modal,
  ModalActions,
  Muted,
  OffsetPager,
  Page,
  PageHeader,
  Pill,
  RowActions,
  Section,
  Select,
  SeverityBadge,
  Spinner,
  Table,
  TableEmpty,
  Tabs,
  Td,
  Textarea,
  Th,
  THead,
  TRow,
  useConfirm,
  type RowAction,
} from "../components/ui";
import {
  collapseSyncRuns,
  formatRefRange,
  formatSyncRunResult,
  formatSyncRunRow,
  shortDigest,
  type SyncRunSummaryView,
} from "../syncRunSummary";
import { parseList } from "../util";

const PAGE_SIZE = 30;
// Stay below the common 8 KiB request-line ceiling used by proxies. For larger
// selections, a named set provides the path-based export endpoint.
const MAX_TEMPLATE_EXPORT_URL_LENGTH = 7_000;

function fmtTime(value?: string) {
  return value ? new Date(value).toLocaleString() : "—";
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
          <DescriptionList columns={2}>
            <Meta label="Template ID">
              <span className="font-mono text-xs">{detail.data.id}</span>
            </Meta>
            <Meta label="Source">{detail.data.source}</Meta>
            <Meta label="Author">{detail.data.author || <Muted />}</Meta>
            <Meta label="Revision">
              <span className="tabular-nums">{detail.data.revision}</span>
            </Meta>
          </DescriptionList>
          {detail.data.description && <p className="text-sm text-neutral-600 dark:text-neutral-400">{detail.data.description}</p>}
          <pre className="max-h-[50dvh] overflow-auto rounded-md bg-neutral-950 p-4 text-xs text-neutral-100">
            {detail.data.yaml}
          </pre>
          <ModalActions>
            <Button onClick={onClose}>Close</Button>
          </ModalActions>
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
          <FormHint>
            Upload or paste one Nuclei YAML document. A healthy scanner node validates it with the
            deployed Nuclei engine before it is saved. The template ID is immutable after creation.
          </FormHint>
          <Field label="Upload a YAML file" hint="Replaces the editor content below.">
            <FileInput
              accept=".yaml,.yml,application/yaml,text/yaml,text/plain"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void file.text().then(setDraft);
              }}
            />
          </Field>
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
          <ModalActions>
            <Button onClick={onClose}>Cancel</Button>
            <Button
              variant="primary"
              disabled={save.isPending || !yaml.trim() || (existing != null && detail.isLoading)}
              onClick={() => save.mutate()}
            >
              {save.isPending ? "Validating and saving…" : "Save template"}
            </Button>
          </ModalActions>
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
  emptyMessage = "No templates match these filters.",
}: {
  templates: Template[];
  selected?: Set<string>;
  onToggle?: (id: string) => void;
  onView: (template: Template) => void;
  actions?: (template: Template) => RowAction[];
  sort?: TemplateSort;
  order?: SortOrder;
  onSort?: (sort: TemplateSort) => void;
  emptyMessage?: string;
}) {
  const header = (label: string, value: TemplateSort) => (
    <Th aria-sort={sort === value ? (order === "desc" ? "descending" : "ascending") : "none"}>
      {onSort ? (
        <button
          type="button"
          className={cn("inline-flex items-center gap-1 rounded-sm uppercase hover:text-indigo-600", focusRing)}
          onClick={() => onSort(value)}
        >
          {label}
          <span aria-hidden="true" className={sort === value ? "text-indigo-600" : "text-neutral-300"}>
            {sort === value ? (order === "desc" ? "↓" : "↑") : "↕"}
          </span>
        </button>
      ) : label}
    </Th>
  );
  return (
    <Table>
      <THead>
        {selected && <Th className="w-10" aria-label="Selected" />}
        {header("Template", "name")}
        {header("Severity", "severity")}
        {header("Source", "source")}
        <Th>Tags</Th>
        {header("Inserted", "inserted")}
        {header("Revision", "revision")}
        <Th aria-label="Actions" />
      </THead>
      <tbody>
        {templates.map((template) => (
          <TRow key={template.id} highlighted={selected?.has(template.id)}>
            {selected && (
              <Td>
                <input
                  type="checkbox"
                  className="h-4 w-4 accent-indigo-600"
                  checked={selected.has(template.id)}
                  onChange={() => onToggle?.(template.id)}
                  aria-label={`Select ${template.id}`}
                />
              </Td>
            )}
            <Td className="max-w-md">
              <button
                type="button"
                className={cn("rounded-sm text-left font-medium hover:text-indigo-600", focusRing)}
                onClick={() => onView(template)}
              >
                {template.name || template.id}
              </button>
              <div className="mt-0.5 truncate font-mono text-xs text-neutral-500" title={template.id}>
                {template.id}
              </div>
            </Td>
            <Td><SeverityBadge severity={template.severity} /></Td>
            <Td>
              <Pill tone={template.source === "custom" ? "good" : "neutral"}>{template.source}</Pill>
            </Td>
            <Td className="max-w-xs text-xs text-neutral-500">
              <span className="line-clamp-2">{template.tags.join(", ") || "—"}</span>
            </Td>
            <Td className="whitespace-nowrap text-xs text-neutral-500">{fmtTime(template.created_at)}</Td>
            <Td className="tabular-nums text-neutral-500">{template.revision}</Td>
            <RowActions
              label={template.id}
              actions={[{ label: "View YAML", primary: true, onSelect: () => onView(template) }, ...(actions?.(template) ?? [])]}
            />
          </TRow>
        ))}
        {templates.length === 0 && <TableEmpty colSpan={selected ? 8 : 7}>{emptyMessage}</TableEmpty>}
      </tbody>
    </Table>
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
    <div className="border-t border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
      <OffsetPager offset={offset} total={total} pageSize={pageSize} onChange={onChange} />
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
  const explicitSets = (sets.data ?? []).filter((set) => set.mode === "exact");
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
      const set = await api.createTemplateSet({ name: setName.trim(), mode: "exact" });
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
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Field label="Search">
            <Input className="w-full" value={query} onChange={(event) => { setQuery(event.target.value); resetPage(); }} placeholder="ID, name, description" />
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
          <Field label="Tags">
            <Input className="w-full" value={tags} onChange={(event) => { setTags(event.target.value); resetPage(); }} placeholder="cve, rce" />
          </Field>
        </div>
      </Card>

      {selected.size > 0 && (
        <Card className="p-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="mr-auto space-y-0.5">
              <div className="font-medium">{selected.size} selected</div>
              <Button variant="link" className="text-xs" onClick={() => setSelected(new Set())}>Clear selection</Button>
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
                  <Input className="w-52 shrink-0" value={setName} onChange={(event) => setSetName(event.target.value)} placeholder="internet-exposure" />
                </Field>
                <Button disabled={!setName.trim() || create.isPending} onClick={() => create.mutate()}>
                  {create.isPending ? "Creating…" : "Create from selection"}
                </Button>
              </>
            )}
          </div>
          {exportTooLarge && (
            <div className="mt-3">
              <FormHint tone="warning">
                This selection is too large for a reliable URL-based export.{" "}
                {canWrite
                  ? "Add it to a template set and export the set instead."
                  : "Ask an operator to save it as a template set, then export the set."}
              </FormHint>
            </div>
          )}
          {download.isError && <div className="mt-3"><ErrorText error={download.error} /></div>}
          {(add.isError || create.isError) && <div className="mt-3"><ErrorText error={add.error ?? create.error} /></div>}
        </Card>
      )}
      {notice && <Alert tone="success" onDismiss={() => setNotice("")}>{notice}</Alert>}
      {selectMatching.isError && <ErrorText error={selectMatching.error} />}

      {templates.isError ? <ErrorText error={templates.error} /> : templates.isLoading || !templates.data ? <Spinner /> : (
        <Card>
          <CardHeader>
            <span className="text-xs text-neutral-500">{templates.data.total} templates match the current filters.</span>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                onClick={() => setSelected((current) => {
                  const next = new Set(current);
                  templates.data.items.forEach((template) => next.add(template.id));
                  return next;
                })}
              >
                Select this page
              </Button>
              <Button
                size="sm"
                disabled={selectMatching.isPending || templates.data.total === 0}
                onClick={() => selectMatching.mutate()}
              >
                {selectMatching.isPending ? "Selecting…" : `Select all ${templates.data.total} matching`}
              </Button>
            </div>
          </CardHeader>
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
  const confirm = useConfirm();
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
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-neutral-500">Organization-specific YAML, validated by Nuclei and stored losslessly alongside the upstream catalog.</p>
        {canWrite && <Button variant="primary" onClick={() => setEditing("new")}>New custom template</Button>}
      </div>
      {notice && <Alert tone="success" onDismiss={() => setNotice("")}>{notice}</Alert>}
      {remove.isError && <ErrorText error={remove.error} />}
      {templates.isError ? <ErrorText error={templates.error} /> : templates.isLoading || !templates.data ? <Spinner /> : (
        <Card>
          <CatalogTable
            templates={templates.data.items}
            onView={setViewing}
            sort={sort}
            order={order}
            onSort={changeSort}
            emptyMessage="No custom templates yet."
            actions={(template) => [
              { label: "Edit", primary: true, hidden: !canWrite, onSelect: () => setEditing(template) },
              {
                label: "Delete",
                danger: true,
                hidden: !canDelete,
                onSelect: async () => {
                  if (
                    await confirm({
                      title: `Delete custom template “${template.id}”?`,
                      description: "Exact template sets that include it lose this member. Deletion is refused while an exclude-mode set lists it.",
                      confirmLabel: "Delete template",
                    })
                  )
                    remove.mutate(template.id);
                },
              },
            ]}
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

function SyncRunRow({
  run,
  result,
  indent = false,
  expander,
}: {
  run: TemplateSyncRun;
  result: SyncRunSummaryView;
  indent?: boolean;
  expander?: ReactNode;
}) {
  const upstream = formatRefRange(run.ref_before, run.ref_after);
  return (
    <TRow>
      <Td className="whitespace-nowrap">
        {indent && <span aria-hidden="true" className="mr-1 text-neutral-400">↳</span>}
        {fmtTime(run.started_at)}
      </Td>
      <Td><Pill tone={run.status === "success" ? "good" : run.status === "failed" ? "warn" : "neutral"}>{run.status}</Pill></Td>
      <Td className="tabular-nums" title={result.title || undefined}>
        {result.text}
        {expander}
      </Td>
      <Td className="whitespace-nowrap">
        {run.templates_commit ? (
          <>
            <div className="font-mono text-xs" title={run.templates_commit}>
              {shortDigest(run.templates_commit)}
            </div>
            <div className="text-xs tabular-nums text-neutral-500">
              {run.template_count ?? 0} templates
            </div>
          </>
        ) : <Muted />}
      </Td>
      <Td className="font-mono text-xs" title={upstream.title || undefined}>
        {upstream.text}
      </Td>
      <Td className="whitespace-nowrap text-neutral-500">{fmtTime(run.finished_at)}</Td>
      <Td className="max-w-md text-xs text-rose-600 dark:text-rose-400" title={run.error}>{run.error || <Muted />}</Td>
    </TRow>
  );
}

function SyncTab({ canWrite }: { canWrite: boolean }) {
  const syncPageSize = 20;
  const qc = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
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
        <Section
          title={
            <span className="flex items-center gap-2">
              Upstream mirror
              <Pill tone={status.data.enabled ? "good" : "warn"}>{status.data.enabled ? "enabled" : "disabled"}</Pill>
            </span>
          }
          actions={
            canWrite && (
              <Button variant="primary" disabled={!status.data.enabled || trigger.isPending} onClick={() => trigger.mutate()}>
                {trigger.isPending ? "Queueing…" : trigger.isSuccess ? "Sync queued" : "Sync now"}
              </Button>
            )
          }
        >
          <div className="space-y-3">
            {status.data.enabled ? (
              <DescriptionList>
                <Meta label="Repository"><span className="break-all font-mono text-xs">{status.data.repo}</span></Meta>
                <Meta label="Ref"><span className="font-mono text-xs">{status.data.ref}</span></Meta>
                <Meta label="Interval">{status.data.interval}</Meta>
                <Meta label="Active catalog bundle">
                  <span className="font-mono text-xs" title={status.data.templates_commit}>
                    {shortDigest(status.data.templates_commit)}
                  </span>
                </Meta>
                <Meta label="Active templates"><span className="tabular-nums">{status.data.template_count}</span></Meta>
              </DescriptionList>
            ) : (
              <p className="text-sm text-neutral-500">Set TEMPLATE_SYNC_REPO to enable the community catalog mirror. Custom templates remain available.</p>
            )}
            <FormHint>
              Configure the mirror on the backend with TEMPLATE_SYNC_REPO, TEMPLATE_SYNC_REF,
              and TEMPLATE_SYNC_INTERVAL. Changes take effect after a backend restart.
            </FormHint>
            {trigger.isError && <ErrorText error={trigger.error} />}
          </div>
        </Section>
      )}

      {runs.isError ? <ErrorText error={runs.error} /> : runs.isLoading || !runs.data ? <Spinner /> : (
        <Card>
          <CardHeader>
            <div>
              <h2 className="text-sm font-semibold">Sync history</h2>
              <div className="text-xs text-neutral-500">
                {runs.data.total} retained {runs.data.total === 1 ? "run" : "runs"} in PostgreSQL.
              </div>
            </div>
          </CardHeader>
          <Table>
              <THead>
                <Th>Started</Th>
                <Th>Status</Th>
                <Th>Result</Th>
                <Th>Catalog bundle</Th>
                <Th>Upstream commit</Th>
                <Th>Finished</Th>
                <Th>Error</Th>
              </THead>
              <tbody>
                {collapseSyncRuns(runs.data.items).map(({ run, count, rest }) => {
                  // Key by the series' oldest run so the group stays stable as
                  // new periodic refreshes arrive on top.
                  const groupKey = rest.length > 0 ? rest[rest.length - 1].id : run.id;
                  const isExpanded = expanded.has(groupKey);
                  return (
                    <Fragment key={groupKey}>
                      <SyncRunRow
                        run={run}
                        result={formatSyncRunRow(run, count, fmtTime(run.finished_at))}
                        expander={count > 1 && (
                          <Button
                            variant="link"
                            aria-expanded={isExpanded}
                            className="ml-2 gap-0.5 align-middle text-xs"
                            onClick={() =>
                              setExpanded((prev) => {
                                const next = new Set(prev);
                                if (next.has(groupKey)) next.delete(groupKey);
                                else next.add(groupKey);
                                return next;
                              })
                            }
                          >
                            {isExpanded ? (
                              <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                            ) : (
                              <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                            )}
                            {isExpanded ? "hide" : `${count - 1} more`}
                          </Button>
                        )}
                      />
                      {isExpanded &&
                        rest.map((older) => (
                          <SyncRunRow key={older.id} run={older} result={formatSyncRunResult(older)} indent />
                        ))}
                    </Fragment>
                  );
                })}
                {runs.data.items.length === 0 && <TableEmpty colSpan={7}>No upstream sync has run yet.</TableEmpty>}
              </tbody>
          </Table>
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
    <Page>
      <PageHeader
        title="Templates"
        description="Browse the mirrored Nuclei catalog, author custom checks, and monitor catalog refreshes."
        actions={canWrite && <Button onClick={() => setImporting(true)}>Import templates</Button>}
      />
      {importNotice && (
        <Alert tone="success" onDismiss={() => setImportNotice("")}>
          {importNotice}
        </Alert>
      )}
      <Tabs
        tabs={[
          { value: "catalog", label: "Catalog" },
          { value: "custom", label: "Custom templates" },
          { value: "sync", label: "Sync" },
        ]}
        value={tab}
        onChange={setTab}
      />
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
          description="Upload a template export in YAML archive or JSON format. This imports custom templates only; use Template sets to restore a set and its membership."
          importArchive={api.importTemplates}
          onImported={imported}
          onClose={() => setImporting(false)}
        />
      )}
    </Page>
  );
}
