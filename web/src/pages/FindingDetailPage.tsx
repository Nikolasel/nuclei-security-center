import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
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
import { safeHref } from "../util";
import { Button, Card, ErrorText, FindingStateBadge, Input, Pill, Select, SeverityBadge, Spinner } from "../components/ui";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="p-4">
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-neutral-500">{title}</h2>
      {children}
    </Card>
  );
}

function Chips({ items, className }: { items?: string[]; className?: string }) {
  if (!items?.length) return <span className="text-neutral-400">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((x) => (
        <span
          key={x}
          className={`rounded bg-neutral-100 px-1.5 py-0.5 text-xs dark:bg-neutral-800 ${className ?? ""}`}
        >
          {x}
        </span>
      ))}
    </div>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-neutral-500">{label}</dt>
      <dd className="break-all">{children}</dd>
    </div>
  );
}

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
    <Card className="space-y-4 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="mr-2 text-sm font-semibold uppercase tracking-wide text-neutral-500">Lifecycle</h2>
        <FindingStateBadge state={f.effective_state} />
        <span className="text-xs text-neutral-500">
          detection: <span className="font-medium text-neutral-700 dark:text-neutral-300">{STATE_LABELS[f.detection_state]}</span>
        </span>
        {f.times_mitigated > 0 && <Pill tone="warn">mitigated ×{f.times_mitigated}</Pill>}
        {!f.auto_mitigation_eligible && (
          <Pill tone="warn">
            <span title="This finding has no network host:port. Scan absence cannot automatically mark it mitigated.">
              auto-mitigation unavailable
            </span>
          </Pill>
        )}
        {f.disposition === "accepted" && f.accept_expires_at && (
          <span className="text-xs text-neutral-500">
            accept expires {new Date(f.accept_expires_at).toLocaleDateString()}
          </span>
        )}
      </div>

      {(f.disposition_by || f.disposition_note) && (
        <p className="text-xs text-neutral-500">
          Disposition <span className="font-medium">{DISPOSITION_LABELS[f.disposition]}</span>
          {f.disposition_by && <> · by {f.disposition_by}</>}
          {f.disposition_at && <> · {new Date(f.disposition_at).toLocaleString()}</>}
          {f.disposition_note && <> — “{f.disposition_note}”</>}
        </p>
      )}
      {f.recast_severity && (
        <p className="text-xs text-neutral-500">
          Severity recast to <span className="font-medium">{f.recast_severity}</span>
          {f.recast_by && <> · by {f.recast_by}</>}
          {f.recast_note && <> — “{f.recast_note}”</>}
        </p>
      )}

      {canTriage ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2 rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
            <div className="text-xs font-semibold uppercase tracking-wide text-neutral-500">Disposition</div>
            <Select value={disposition} onChange={(e) => setDisposition(e.target.value as Disposition)}>
              {DISPOSITIONS.map((d) => (
                <option key={d} value={d}>
                  {DISPOSITION_LABELS[d]}
                </option>
              ))}
            </Select>
            {disposition === "accepted" && (
              <label className="block space-y-1">
                <span className="block text-xs text-neutral-500">Accept until (optional)</span>
                <Input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
              </label>
            )}
            <Input value={dispNote} onChange={(e) => setDispNote(e.target.value)} placeholder="note (optional)…" />
            <Button variant="primary" disabled={!dispDirty || dispMut.isPending} onClick={() => dispMut.mutate()}>
              {dispMut.isPending ? "Saving…" : "Save disposition"}
            </Button>
            {dispMut.isError && <ErrorText error={dispMut.error} />}
          </div>

          <div className="space-y-2 rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
            <div className="text-xs font-semibold uppercase tracking-wide text-neutral-500">Recast severity</div>
            <Select value={recast} onChange={(e) => setRecast(e.target.value)}>
              <option value="">— no recast (observed: {f.severity}) —</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
            <Input value={recastNote} onChange={(e) => setRecastNote(e.target.value)} placeholder="note (optional)…" />
            <Button variant="primary" disabled={!recastDirty || recastMut.isPending} onClick={() => recastMut.mutate()}>
              {recastMut.isPending ? "Saving…" : recast ? "Save recast" : "Clear recast"}
            </Button>
            {recastMut.isError && <ErrorText error={recastMut.error} />}
          </div>
        </div>
      ) : (
        <p className="text-xs text-neutral-400">Operator role required to change disposition or severity.</p>
      )}
    </Card>
  );
}

export function FindingDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  // Go back to the findings list preserving its filter: when we arrived here from
  // within the app, pop history (which restores /findings?filter=… with its URL
  // state). A direct visit (no in-app history) falls back to the bare list.
  const backToFindings = () => {
    if (location.key !== "default") navigate(-1);
    else navigate("/findings");
  };
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api.getFinding(id) });
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

  return (
    <div className="space-y-5">
      <div>
        <button
          type="button"
          onClick={backToFindings}
          className="text-sm text-indigo-600 hover:underline dark:text-indigo-400"
        >
          ← Findings
        </button>
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <SeverityBadge severity={f.effective_severity} recast={!!f.recast_severity} />
          <h1 className="text-xl font-semibold">{name}</h1>
          <FindingStateBadge state={f.effective_state} />
        </div>
      </div>

      <TriagePanel f={f} />

      <Section title="Overview">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
          <Meta label="Host">{f.host || "—"}</Meta>
          <Meta label="Matched at">
            <span className="font-mono text-xs">{raw["matched-at"] || f.matched_at || "—"}</span>
          </Meta>
          <Meta label="Type">{raw.type || f.type || "—"}</Meta>
          <Meta label="Occurrences">{f.occurrence_count}</Meta>
          <Meta label="Targets">
            {(f.target_ids ?? []).length ? (
              <div className="flex flex-wrap gap-1">
                {(f.target_ids ?? []).map((targetID) => (
                  <Link
                    key={targetID}
                    to={`/targets?target=${encodeURIComponent(targetID)}`}
                    title={targetID}
                    className="text-xs text-indigo-600 hover:underline dark:text-indigo-400"
                  >
                    {targetNames.get(targetID) ?? targetID}
                  </Link>
                ))}
              </div>
            ) : (
              <span className="text-neutral-400">ad-hoc only</span>
            )}
          </Meta>
          <Meta label="Template">
            <Link
              to={`/templates?template=${encodeURIComponent(f.template_id)}`}
              target="_blank"
              rel="noopener noreferrer"
              title="Open the NSC template in a new tab"
              className="font-mono text-xs text-indigo-600 hover:underline dark:text-indigo-400"
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
                  className="text-xs text-neutral-500 hover:underline"
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
                className="text-indigo-600 hover:underline dark:text-indigo-400"
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
                className="text-indigo-600 hover:underline dark:text-indigo-400"
                title={new Date(f.last_seen_at).toLocaleString()}
              >
                {new Date(f.last_seen_at).toLocaleDateString()}
              </Link>
            ) : (
              new Date(f.last_seen_at).toLocaleDateString()
            )}
          </Meta>
        </dl>
      </Section>

      {(cls["cve-id"]?.length || cls["cwe-id"]?.length || cls["cvss-score"] != null || cls["cvss-metrics"]) && (
        <Section title="Classification">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-4">
            <Meta label="CVE">
              {cls["cve-id"]?.length ? (
                <div className="flex flex-wrap gap-1">
                  {cls["cve-id"].map((cve) => (
                    <a
                      key={cve}
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noreferrer"
                      className="rounded bg-red-100 px-1.5 py-0.5 text-xs font-medium text-red-800 hover:underline dark:bg-red-950 dark:text-red-300"
                    >
                      {cve}
                    </a>
                  ))}
                </div>
              ) : (
                <span className="text-neutral-400">—</span>
              )}
            </Meta>
            <Meta label="CWE">
              <Chips items={cls["cwe-id"]} />
            </Meta>
            <Meta label="CVSS">
              {cls["cvss-score"] != null ? `${cls["cvss-score"]}` : "—"}
            </Meta>
            <Meta label="CVSS vector">
              <span className="font-mono text-xs">{cls["cvss-metrics"] || "—"}</span>
            </Meta>
          </dl>
        </Section>
      )}

      {info.description && (
        <Section title="Description">
          <p className="whitespace-pre-wrap text-sm">{info.description}</p>
        </Section>
      )}

      {(info.tags?.length || info.author?.length) && (
        <Section title="Metadata">
          <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
            <Meta label="Tags">
              <Chips items={info.tags} />
            </Meta>
            <Meta label="Author">
              <Chips items={info.author} />
            </Meta>
          </dl>
        </Section>
      )}

      {raw["extracted-results"]?.length ? (
        <Section title="Extracted results">
          <ul className="list-inside list-disc space-y-1 text-sm">
            {raw["extracted-results"].map((r, i) => (
              <li key={i} className="font-mono text-xs">
                {r}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

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
                      className="break-all text-indigo-600 hover:underline dark:text-indigo-400"
                    >
                      {r}
                    </a>
                  ) : (
                    <span className="break-all text-slate-600 dark:text-slate-400">{r}</span>
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
            <summary className="cursor-pointer text-sm text-neutral-500">Show raw JSON</summary>
            <div className="mt-2">
              <CodeBlock text={JSON.stringify(f.raw, null, 2)} />
            </div>
          </details>
        </Section>
      )}
    </div>
  );
}
