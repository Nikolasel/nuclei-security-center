import { useQuery } from "@tanstack/react-query";
import { type ReactNode } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { api, type NucleiRaw } from "../api";
import { CodeBlock } from "../components/CodeBlock";
import { safeHref } from "../util";
import { Card, ErrorText, SeverityBadge, Spinner } from "../components/ui";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="p-4">
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-neutral-500">{title}</h2>
      {children}
    </Card>
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

function Chips({ items }: { items?: string[] }) {
  if (!items?.length) return <span className="text-neutral-400">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((item, index) => (
        <span key={`${item}-${index}`} className="rounded bg-neutral-100 px-1.5 py-0.5 text-xs dark:bg-neutral-800">
          {item}
        </span>
      ))}
    </div>
  );
}

/** One immutable result exactly as its scan produced it. This page deliberately
 * does not substitute or redirect to the globally merged lifecycle finding. */
export function OccurrenceDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const query = useQuery({ queryKey: ["occurrence", id], queryFn: () => api.getOccurrence(id) });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const targetName = targets.data?.find((target) => target.id === query.data?.target_id)?.name;

  if (query.isLoading) return <Spinner />;
  if (query.isError) return <ErrorText error={query.error} />;
  if (!query.data) return null;

  const occurrence = query.data;
  const raw: NucleiRaw = occurrence.raw ?? {};
  const info = raw.info ?? {};
  const classification = info.classification ?? {};
  const name = info.name || occurrence.name || occurrence.template_id;
  const back = () => {
    if (location.key !== "default") navigate(-1);
    else navigate(`/scans/${occurrence.scan_id}`);
  };

  return (
    <div className="space-y-5">
      <div>
        <button
          type="button"
          onClick={back}
          className="text-sm text-indigo-600 hover:underline dark:text-indigo-400"
        >
          ← Scan results
        </button>
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <SeverityBadge severity={occurrence.severity} />
          <h1 className="text-xl font-semibold">{name}</h1>
          <span className="rounded bg-neutral-100 px-2 py-1 text-xs text-neutral-600 dark:bg-neutral-800 dark:text-neutral-300">
            exact scan occurrence
          </span>
        </div>
      </div>

      <Section title="Occurrence">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
          <Meta label="Scan">
            <Link to={`/scans/${occurrence.scan_id}`} className="font-mono text-xs text-indigo-600 hover:underline dark:text-indigo-400">
              {occurrence.scan_id}
            </Link>
          </Meta>
          <Meta label="Observed at">{new Date(occurrence.created_at).toLocaleString()}</Meta>
          <Meta label="Target">
            {occurrence.target_id ? (
              <Link
                to={`/targets?target=${encodeURIComponent(occurrence.target_id)}`}
                title={occurrence.target_id}
                className="text-xs text-indigo-600 hover:underline dark:text-indigo-400"
              >
                {targetName ?? occurrence.target_id}
              </Link>
            ) : (
              <span className="text-neutral-400">ad-hoc</span>
            )}
          </Meta>
          <Meta label="Host">{occurrence.host || raw.host || "—"}</Meta>
          <Meta label="Matched at">
            <span className="font-mono text-xs">{raw["matched-at"] || occurrence.matched_at || "—"}</span>
          </Meta>
          <Meta label="Type">{raw.type || occurrence.type || "—"}</Meta>
          <Meta label="Template">
            <Link
              to={`/templates?template=${encodeURIComponent(occurrence.template_id)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-xs text-indigo-600 hover:underline dark:text-indigo-400"
            >
              {occurrence.template_id}
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
          <Meta label="Matcher">{raw["matcher-name"] || "—"}</Meta>
          <Meta label="Extractor">{raw["extractor-name"] || "—"}</Meta>
        </dl>
      </Section>

      {(classification["cve-id"]?.length ||
        classification["cwe-id"]?.length ||
        classification["cvss-score"] != null ||
        classification["cvss-metrics"]) && (
        <Section title="Classification">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-4">
            <Meta label="CVE"><Chips items={classification["cve-id"]} /></Meta>
            <Meta label="CWE"><Chips items={classification["cwe-id"]} /></Meta>
            <Meta label="CVSS">{classification["cvss-score"] ?? "—"}</Meta>
            <Meta label="CVSS vector">
              <span className="font-mono text-xs">{classification["cvss-metrics"] || "—"}</span>
            </Meta>
          </dl>
        </Section>
      )}

      {info.description && (
        <Section title="Description">
          <p className="whitespace-pre-wrap text-sm">{info.description}</p>
        </Section>
      )}

      {raw["extracted-results"]?.length ? (
        <Section title="Extracted results"><Chips items={raw["extracted-results"]} /></Section>
      ) : null}

      {raw["curl-command"] && <Section title="Reproduce (curl)"><CodeBlock text={raw["curl-command"]} /></Section>}
      {raw.request && <Section title="Request"><CodeBlock text={raw.request} /></Section>}
      {raw.response && <Section title="Response"><CodeBlock text={raw.response} /></Section>}

      {info.reference?.length ? (
        <Section title="References">
          <ul className="space-y-1 text-sm">
            {info.reference.map((reference) => {
              const href = safeHref(reference);
              return (
                <li key={reference}>
                  {href ? (
                    <a href={href} target="_blank" rel="noreferrer" className="break-all text-indigo-600 hover:underline dark:text-indigo-400">
                      {reference}
                    </a>
                  ) : (
                    <span className="break-all text-slate-600 dark:text-slate-400">{reference}</span>
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

      <Section title="Raw occurrence">
        <details>
          <summary className="cursor-pointer text-sm text-neutral-500">Show exact raw JSON</summary>
          <div className="mt-2"><CodeBlock text={JSON.stringify(occurrence.raw, null, 2)} /></div>
        </details>
      </Section>
    </div>
  );
}
