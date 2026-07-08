import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  FINDING_STATUSES,
  STATUS_LABELS,
  type FindingDetail,
  type FindingStatus,
  type NucleiRaw,
} from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Pill, Select, SeverityBadge, Spinner, StatusBadge } from "../components/ui";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="p-4">
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-neutral-500">{title}</h2>
      {children}
    </Card>
  );
}

function CodeBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  };
  return (
    <div className="relative">
      <Button
        variant="secondary"
        onClick={copy}
        className="absolute right-2 top-2 px-2 py-1 text-xs"
      >
        {copied ? "Copied" : "Copy"}
      </Button>
      <pre className="max-h-96 overflow-auto rounded-md bg-neutral-950 p-3 pr-16 text-xs leading-relaxed text-neutral-200">
        {text}
      </pre>
    </div>
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

/** TriagePanel shows lifecycle state (status, new/resolved, first/last seen) and,
 *  for operators, lets the user change the triage status with an optional note. */
function TriagePanel({ f }: { f: FindingDetail }) {
  const me = useMe();
  const canTriage = hasRole(me.data ?? undefined, "operator");
  const qc = useQueryClient();

  const [status, setStatus] = useState<FindingStatus>(f.status);
  const [note, setNote] = useState("");

  // Keep the control in sync when the finding reloads (e.g. after a save).
  useEffect(() => setStatus(f.status), [f.status]);

  const mutation = useMutation({
    mutationFn: () => api.updateFindingStatus(f.id, { status, note: note.trim() || undefined }),
    onSuccess: (updated) => {
      qc.setQueryData(["finding", String(f.id)], updated);
      qc.invalidateQueries({ queryKey: ["findings"] });
      setNote("");
    },
  });

  const dirty = status !== f.status || note.trim() !== "";

  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="mr-2 text-sm font-semibold uppercase tracking-wide text-neutral-500">Triage</h2>
        <StatusBadge status={f.status} />
        {f.new && <Pill tone="new">New</Pill>}
        {f.resolved && <Pill tone="resolved">Resolved · not seen in latest scan</Pill>}
      </div>

      {(f.status_by || f.status_note) && (
        <p className="mt-2 text-xs text-neutral-500">
          {f.status_by && <>Set by {f.status_by}</>}
          {f.status_at && <> · {new Date(f.status_at).toLocaleString()}</>}
          {f.status_note && <> — “{f.status_note}”</>}
        </p>
      )}

      {canTriage ? (
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <label className="space-y-1">
            <span className="block text-xs font-medium text-neutral-500">Set status</span>
            <Select value={status} onChange={(e) => setStatus(e.target.value as FindingStatus)}>
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABELS[s]}
                </option>
              ))}
            </Select>
          </label>
          <label className="flex-1 space-y-1" style={{ minWidth: "16rem" }}>
            <span className="block text-xs font-medium text-neutral-500">Note (optional)</span>
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="why this status…"
              className="w-full rounded-md border border-neutral-300 bg-white px-3 py-1.5 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-800"
            />
          </label>
          <Button variant="primary" disabled={!dirty || mutation.isPending} onClick={() => mutation.mutate()}>
            {mutation.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      ) : (
        <p className="mt-2 text-xs text-neutral-400">Operator role required to change status.</p>
      )}
      {mutation.isError && <ErrorText error={mutation.error} />}
    </Card>
  );
}

export function FindingDetailPage() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api.getFinding(id) });

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
        <Link to="/findings" className="text-sm text-indigo-600 hover:underline dark:text-indigo-400">
          ← Findings
        </Link>
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <SeverityBadge severity={f.severity} />
          <h1 className="text-xl font-semibold">{name}</h1>
          <StatusBadge status={f.status} />
          {f.new && <Pill tone="new">New</Pill>}
          {f.resolved && <Pill tone="resolved">Resolved</Pill>}
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
          <Meta label="Template">
            {raw["template-url"] ? (
              <a
                href={raw["template-url"]}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-xs text-indigo-600 hover:underline dark:text-indigo-400"
              >
                {f.template_id}
              </a>
            ) : (
              <span className="font-mono text-xs">{f.template_id}</span>
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
            {info.reference.map((r) => (
              <li key={r}>
                <a
                  href={r}
                  target="_blank"
                  rel="noreferrer"
                  className="break-all text-indigo-600 hover:underline dark:text-indigo-400"
                >
                  {r}
                </a>
              </li>
            ))}
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
