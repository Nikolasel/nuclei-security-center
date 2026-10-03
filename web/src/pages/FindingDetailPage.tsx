import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import {
  api,
  DISPOSITION_LABELS,
  DISPOSITIONS,
  SEVERITIES,
  STATE_LABELS,
  type Disposition,
  type FindingDetail,
  type NucleiRaw,
} from "../api";
import { hasRole, useMe } from "../auth";
import { CodeBlock } from "../components/CodeBlock";
import { ExtractedResults } from "../components/ExtractedResults";
import { safeHref } from "../util";
import {
  Button,
  Card,
  DescriptionList,
  ErrorText,
  Field,
  FindingStateBadge,
  FormHint,
  Input,
  linkClass,
  Meta,
  Muted,
  OffsetPager,
  Page,
  PageHeader,
  Pill,
  Section,
  Select,
  SeverityBadge,
  Spinner,
  Table,
  TagList,
  Td,
  Th,
  THead,
  TRow,
} from "../components/ui";

/** TriagePanel shows the Tenable-style lifecycle (effective + detection state,
 *  mitigation history, disposition + recast audit) and, for operators, lets the
 *  user Accept Risk (with optional expiry) / mark False Positive / recast severity.
 *  There is no manual "fixed" — mitigation is evidence-driven. */
function TriagePanel({ f }: { f: FindingDetail }) {
  const me = useMe();
  const canTriage = hasRole(me.data ?? undefined, "operator");
  const qc = useQueryClient();

  const isoDate = (iso?: string) => (iso ? iso.slice(0, 10) : "");
  const [disposition, setDisposition] = useState<Disposition>(f.disposition);
  const [expires, setExpires] = useState(isoDate(f.accept_expires_at));
  const [dispNote, setDispNote] = useState("");
  const [recast, setRecast] = useState(f.recast_severity ?? "");
  const [recastNote, setRecastNote] = useState("");

  // Re-sync controls when the finding reloads (e.g. after a save).
  useEffect(() => {
    setDisposition(f.disposition);
    setExpires(isoDate(f.accept_expires_at));
    setRecast(f.recast_severity ?? "");
  }, [f.disposition, f.accept_expires_at, f.recast_severity]);

  const onSaved = (updated: FindingDetail) => {
    qc.setQueryData(["finding", String(f.id)], updated);
    qc.invalidateQueries({ queryKey: ["findings"] });
  };

  const dispMut = useMutation({
    mutationFn: () =>
      api.setDisposition(f.id, {
        disposition,
        note: dispNote.trim() || undefined,
        accept_expires_at:
          disposition === "accepted" && expires ? new Date(`${expires}T00:00:00Z`).toISOString() : null,
      }),
    onSuccess: (u) => {
      onSaved(u);
      setDispNote("");
    },
  });

  const recastMut = useMutation({
    mutationFn: () => api.recastSeverity(f.id, { severity: recast, note: recastNote.trim() || undefined }),
    onSuccess: (u) => {
      onSaved(u);
      setRecastNote("");
    },
  });

  const dispDirty =
    disposition !== f.disposition ||
    dispNote.trim() !== "" ||
    (disposition === "accepted" && expires !== isoDate(f.accept_expires_at));
  const recastDirty = recast !== (f.recast_severity ?? "") || recastNote.trim() !== "";

  return (
    <Section
      title="Lifecycle"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <FindingStateBadge state={f.effective_state} />
          <span className="text-xs text-neutral-500">
            detection:{" "}
            <span className="font-medium text-neutral-700 dark:text-neutral-300">{STATE_LABELS[f.detection_state]}</span>
          </span>
          {f.times_mitigated > 0 && <Pill tone="warn">mitigated ×{f.times_mitigated}</Pill>}
          {!f.auto_mitigation_eligible && (
            <Pill tone="warn" title="This finding has no network host:port. Scan absence cannot automatically mark it mitigated.">
              auto-mitigation unavailable
            </Pill>
          )}
          {f.disposition === "accepted" && f.accept_expires_at && (
            <span className="text-xs text-neutral-500">
              accept expires {new Date(f.accept_expires_at).toLocaleDateString()}
            </span>
          )}
        </div>
      }
    >
      <div className="space-y-4">
        {(f.disposition_by || f.disposition_note) && (
          <FormHint>
            Disposition <span className="font-medium">{DISPOSITION_LABELS[f.disposition]}</span>
            {f.disposition_by && <> · by {f.disposition_by}</>}
            {f.disposition_at && <> · {new Date(f.disposition_at).toLocaleString()}</>}
            {f.disposition_note && <> — “{f.disposition_note}”</>}
          </FormHint>
        )}
        {f.recast_severity && (
          <FormHint>
            Severity recast to <span className="font-medium">{f.recast_severity}</span>
            {f.recast_by && <> · by {f.recast_by}</>}
            {f.recast_note && <> — “{f.recast_note}”</>}
          </FormHint>
        )}

        {canTriage ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <Card className="space-y-3 p-4 shadow-none">
              <Field label="Disposition">
                <Select
                  value={disposition}
                  onChange={(e) => setDisposition(e.target.value as Disposition)}
                  className="w-full"
                >
                  {DISPOSITIONS.map((d) => (
                    <option key={d} value={d}>
                      {DISPOSITION_LABELS[d]}
                    </option>
                  ))}
                </Select>
              </Field>
              {disposition === "accepted" && (
                <Field label="Accept until" hint="Optional. An expired acceptance falls back to the detection state.">
                  <Input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} className="w-full" />
                </Field>
              )}
              <Field label="Note">
                <Input value={dispNote} onChange={(e) => setDispNote(e.target.value)} placeholder="Optional" className="w-full" />
              </Field>
              {dispMut.isError && <ErrorText error={dispMut.error} />}
              <Button variant="primary" disabled={!dispDirty || dispMut.isPending} onClick={() => dispMut.mutate()}>
                {dispMut.isPending ? "Saving…" : "Save disposition"}
              </Button>
            </Card>

            <Card className="space-y-3 p-4 shadow-none">
              <Field label="Recast severity">
                <Select value={recast} onChange={(e) => setRecast(e.target.value)} className="w-full">
                  <option value="">— no recast (observed: {f.severity}) —</option>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Note">
                <Input value={recastNote} onChange={(e) => setRecastNote(e.target.value)} placeholder="Optional" className="w-full" />
              </Field>
              {recastMut.isError && <ErrorText error={recastMut.error} />}
              <Button variant="primary" disabled={!recastDirty || recastMut.isPending} onClick={() => recastMut.mutate()}>
                {recastMut.isPending ? "Saving…" : recast ? "Save recast" : "Clear recast"}
              </Button>
            </Card>
          </div>
        ) : (
          <FormHint>Operator role required to change disposition or severity.</FormHint>
        )}
      </div>
    </Section>
  );
}

const OCCURRENCE_PAGE_SIZE = 50;

export function FindingDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const [occOffset, setOccOffset] = useState(0);
  // Go back to the findings list preserving its filter: when we arrived here from
  // within the app, pop history (which restores /findings?filter=… with its URL
  // state). A direct visit (no in-app history) falls back to the bare list.
  const backToFindings = () => {
    if (location.key !== "default") navigate(-1);
    else navigate("/findings");
  };
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api.getFinding(id) });
  const occurrences = useQuery({
    queryKey: ["finding-occurrences", id, occOffset],
    queryFn: () => api.listFindingOccurrences(id, { limit: OCCURRENCE_PAGE_SIZE, offset: occOffset }),
    enabled: q.isSuccess,
  });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const targetNames = new Map((targets.data ?? []).map((target) => [target.id, target.name]));

  if (q.isLoading) return <Spinner />;
  if (q.isError) return <ErrorText error={q.error} />;
  if (!q.data) return null;

  const f = q.data;
  const raw: NucleiRaw = f.raw ?? {};
  const info = raw.info ?? {};
  const cls = info.classification ?? {};
  const name = info.name || f.name || f.template_id;
  const extracted = f.extracted_results?.length ? f.extracted_results : raw["extracted-results"];

  return (
    <Page>
      <PageHeader
        back={{ label: "Findings", onClick: backToFindings }}
        title={name}
        badges={
          <>
            <SeverityBadge severity={f.effective_severity} recast={!!f.recast_severity} />
            <FindingStateBadge state={f.effective_state} />
          </>
        }
      />

      <TriagePanel f={f} />

      <Section title="Overview">
        <DescriptionList>
          <Meta label="Host">{f.host || "—"}</Meta>
          <Meta label="Matched at">
            <span className="font-mono text-xs">{raw["matched-at"] || f.matched_at || "—"}</span>
          </Meta>
          <Meta label="Type">{raw.type || f.type || "—"}</Meta>
          <Meta label="Occurrences">
            <span>{f.occurrence_count}</span>
            {f.latest_occurrence_id != null && (
              <>
                {" "}
                <Link
                  to={`/occurrences/${f.latest_occurrence_id}`}
                  className={linkClass}
                >
                  latest
                </Link>
              </>
            )}
          </Meta>
          <Meta label="Targets">
            {(f.target_ids ?? []).length ? (
              <div className="flex flex-wrap gap-1">
                {(f.target_ids ?? []).map((targetID) => (
                  <Link
                    key={targetID}
                    to={`/targets?target=${encodeURIComponent(targetID)}`}
                    title={targetID}
                    className={`text-xs ${linkClass}`}
                  >
                    {targetNames.get(targetID) ?? targetID}
                  </Link>
                ))}
              </div>
            ) : (
              <Muted>ad-hoc only</Muted>
            )}
          </Meta>
          <Meta label="Template">
            <Link
              to={`/templates?template=${encodeURIComponent(f.template_id)}`}
              target="_blank"
              rel="noopener noreferrer"
              title="Open the NSC template in a new tab"
              className={`font-mono text-xs ${linkClass}`}
            >
              {f.template_id}
            </Link>
            {safeHref(raw["template-url"]) && (
              <>
                {" "}
                <a
                  href={safeHref(raw["template-url"])}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-sm text-xs text-neutral-500 hover:underline"
                >
                  upstream
                </a>
              </>
            )}
          </Meta>
          <Meta label="First seen">
            {f.first_seen_scan ? (
              <Link
                to={`/scans/${f.first_seen_scan}`}
                className={linkClass}
                title={new Date(f.first_seen_at).toLocaleString()}
              >
                {new Date(f.first_seen_at).toLocaleDateString()}
              </Link>
            ) : (
              new Date(f.first_seen_at).toLocaleDateString()
            )}
          </Meta>
          <Meta label="Last seen">
            {f.last_seen_scan ? (
              <Link
                to={`/scans/${f.last_seen_scan}`}
                className={linkClass}
                title={new Date(f.last_seen_at).toLocaleString()}
              >
                {new Date(f.last_seen_at).toLocaleDateString()}
              </Link>
            ) : (
              new Date(f.last_seen_at).toLocaleDateString()
            )}
          </Meta>
        </DescriptionList>
      </Section>

      <Section
        title="Occurrences"
        description="Retained per-scan observations of this finding, newest first. Occurrences from scans removed by retention are deleted with those scans and are not listed here."
        actions={
          f.latest_occurrence_id != null && (
            <Link to={`/occurrences/${f.latest_occurrence_id}`} className={`text-sm ${linkClass}`}>
              Open latest occurrence
            </Link>
          )
        }
      >
        {occurrences.isLoading && <Spinner />}
        {occurrences.isError && <ErrorText error={occurrences.error} />}
        {occurrences.data && (
          <>
            <div className="-mx-4 border-t border-neutral-200 sm:-mx-5 dark:border-neutral-800">
              <Table>
                <THead>
                  <Th>Seen</Th>
                  <Th>Scan</Th>
                  <Th>Target</Th>
                  <Th>Host</Th>
                  <Th>Matched at</Th>
                  <Th aria-label="Open" />
                </THead>
                <tbody>
                  {occurrences.data.items.map((row) => (
                    <TRow key={row.id}>
                      <Td className="whitespace-nowrap">
                        {new Date(row.created_at).toLocaleString()}
                        {row.id === f.latest_occurrence_id && (
                          <span className="ml-2 text-xs text-neutral-500">latest</span>
                        )}
                      </Td>
                      <Td>
                        <Link to={`/scans/${row.scan_id}`} title={row.scan_id} className={`font-mono text-xs ${linkClass}`}>
                          {row.scan_id.slice(0, 8)}
                        </Link>
                      </Td>
                      <Td>
                        {row.target_id ? (
                          <Link
                            to={`/targets?target=${encodeURIComponent(row.target_id)}`}
                            title={row.target_id}
                            className={linkClass}
                          >
                            {targetNames.get(row.target_id) ?? row.target_id}
                          </Link>
                        ) : (
                          <Muted>ad-hoc</Muted>
                        )}
                      </Td>
                      <Td className="break-all">{row.host || <Muted />}</Td>
                      <Td>
                        <span className="font-mono text-xs">{row.matched_at || "—"}</span>
                      </Td>
                      <Td className="text-right">
                        <Link to={`/occurrences/${row.id}`} className={linkClass}>
                          Open
                        </Link>
                      </Td>
                    </TRow>
                  ))}
                </tbody>
              </Table>
            </div>
            <OffsetPager
              className="mt-3"
              offset={occOffset}
              total={occurrences.data.total}
              pageSize={OCCURRENCE_PAGE_SIZE}
              onChange={setOccOffset}
            />
          </>
        )}
      </Section>

      <Section title="Result identity">
        <DescriptionList>
          <Meta label="Matcher">
            <span className="font-mono text-xs">{f.matcher_name || raw["matcher-name"] || "—"}</span>
          </Meta>
          <Meta label="Extractor">
            <span className="font-mono text-xs">{f.extractor_name || raw["extractor-name"] || "—"}</span>
          </Meta>
          <Meta label="Extracted results">
            {extracted?.length ? <ExtractedResults items={extracted} /> : <Muted />}
          </Meta>
        </DescriptionList>
      </Section>

      {(cls["cve-id"]?.length || cls["cwe-id"]?.length || cls["cvss-score"] != null || cls["cvss-metrics"]) && (
        <Section title="Classification">
          <DescriptionList columns={4}>
            <Meta label="CVE">
              {cls["cve-id"]?.length ? (
                <div className="flex flex-wrap gap-1">
                  {cls["cve-id"].map((cve) => (
                    <a
                      key={cve}
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noreferrer"
                      className="rounded bg-red-100 px-1.5 py-0.5 font-mono text-xs font-medium text-red-800 hover:underline dark:bg-red-950 dark:text-red-300"
                    >
                      {cve}
                    </a>
                  ))}
                </div>
              ) : (
                <Muted />
              )}
            </Meta>
            <Meta label="CWE">
              <TagList items={cls["cwe-id"]} />
            </Meta>
            <Meta label="CVSS">
              {cls["cvss-score"] != null ? `${cls["cvss-score"]}` : "—"}
            </Meta>
            <Meta label="CVSS vector">
              <span className="font-mono text-xs">{cls["cvss-metrics"] || "—"}</span>
            </Meta>
          </DescriptionList>
        </Section>
      )}

      {info.description && (
        <Section title="Description">
          <p className="whitespace-pre-wrap text-sm">{info.description}</p>
        </Section>
      )}

      {(info.tags?.length || info.author?.length) && (
        <Section title="Metadata">
          <DescriptionList columns={2}>
            <Meta label="Tags">
              <TagList items={info.tags} />
            </Meta>
            <Meta label="Author">
              <TagList items={info.author} />
            </Meta>
          </DescriptionList>
        </Section>
      )}

      {raw["curl-command"] && (
        <Section title="Reproduce (curl)">
          <CodeBlock text={raw["curl-command"]} />
        </Section>
      )}

      {raw.request && (
        <Section title="Request">
          <CodeBlock text={raw.request} />
        </Section>
      )}

      {raw.response && (
        <Section title="Response">
          <CodeBlock text={raw.response} />
        </Section>
      )}

      {info.reference?.length ? (
        <Section title="References">
          <ul className="space-y-1 text-sm">
            {info.reference.map((r) => {
              const href = safeHref(r);
              return (
                <li key={r}>
                  {href ? (
                    <a
                      href={href}
                      target="_blank"
                      rel="noreferrer"
                      className={`break-all ${linkClass}`}
                    >
                      {r}
                    </a>
                  ) : (
                    <span className="break-all text-neutral-600 dark:text-neutral-400">{r}</span>
                  )}
                </li>
              );
            })}
          </ul>
        </Section>
      ) : null}

      {info.remediation && (
        <Section title="Remediation">
          <p className="whitespace-pre-wrap text-sm">{info.remediation}</p>
        </Section>
      )}

      {f.raw && (
        <Section title="Raw finding">
          <details>
            <summary className="cursor-pointer text-sm text-neutral-500 hover:text-neutral-800 dark:hover:text-neutral-200">Show raw JSON</summary>
            <div className="mt-2">
              <CodeBlock text={JSON.stringify(f.raw, null, 2)} />
            </div>
          </details>
        </Section>
      )}
    </Page>
  );
}
