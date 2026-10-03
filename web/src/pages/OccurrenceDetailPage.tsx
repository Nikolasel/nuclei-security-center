import { useQuery } from "@tanstack/react-query";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { api, type NucleiRaw } from "../api";
import { CodeBlock } from "../components/CodeBlock";
import { ExtractedResults } from "../components/ExtractedResults";
import { safeHref } from "../util";
import {
  Badge,
  DescriptionList,
  ErrorText,
  linkClass,
  Meta,
  Muted,
  Page,
  PageHeader,
  Section,
  SeverityBadge,
  Spinner,
  TagList,
} from "../components/ui";

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
    <Page>
      <PageHeader
        back={{ label: "Scan results", onClick: back }}
        title={name}
        badges={
          <>
            <SeverityBadge severity={occurrence.severity} />
            <Badge>exact scan occurrence</Badge>
          </>
        }
      />

      <Section title="Occurrence">
        <DescriptionList>
          <Meta label="Scan">
            <Link to={`/scans/${occurrence.scan_id}`} className={`font-mono text-xs ${linkClass}`}>
              {occurrence.scan_id}
            </Link>
          </Meta>
          <Meta label="Observed at">{new Date(occurrence.created_at).toLocaleString()}</Meta>
          <Meta label="Lifecycle finding">
            {occurrence.finding_id != null ? (
              <Link
                to={`/findings/${occurrence.finding_id}`}
                className={linkClass}
              >
                Open merged finding
              </Link>
            ) : (
              <Muted />
            )}
          </Meta>
          <Meta label="Target">
            {occurrence.target_id ? (
              <Link
                to={`/targets?target=${encodeURIComponent(occurrence.target_id)}`}
                title={occurrence.target_id}
                className={`text-xs ${linkClass}`}
              >
                {targetName ?? occurrence.target_id}
              </Link>
            ) : (
              <Muted>ad-hoc</Muted>
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
              className={`font-mono text-xs ${linkClass}`}
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
                  className="rounded-sm text-xs text-neutral-500 hover:underline"
                >
                  upstream
                </a>
              </>
            )}
          </Meta>
          <Meta label="Matcher">
            <span className="font-mono text-xs">{occurrence.matcher_name || raw["matcher-name"] || "—"}</span>
          </Meta>
          <Meta label="Extractor">
            <span className="font-mono text-xs">{occurrence.extractor_name || raw["extractor-name"] || "—"}</span>
          </Meta>
        </DescriptionList>
      </Section>

      {(classification["cve-id"]?.length ||
        classification["cwe-id"]?.length ||
        classification["cvss-score"] != null ||
        classification["cvss-metrics"]) && (
        <Section title="Classification">
          <DescriptionList columns={4}>
            <Meta label="CVE"><TagList items={classification["cve-id"]} /></Meta>
            <Meta label="CWE"><TagList items={classification["cwe-id"]} /></Meta>
            <Meta label="CVSS">{classification["cvss-score"] ?? "—"}</Meta>
            <Meta label="CVSS vector">
              <span className="font-mono text-xs">{classification["cvss-metrics"] || "—"}</span>
            </Meta>
          </DescriptionList>
        </Section>
      )}

      {info.description && (
        <Section title="Description">
          <p className="whitespace-pre-wrap text-sm">{info.description}</p>
        </Section>
      )}

      {(occurrence.extracted_results?.length || raw["extracted-results"]?.length) ? (
        <Section title="Extracted results">
          <ExtractedResults items={occurrence.extracted_results?.length ? occurrence.extracted_results : raw["extracted-results"]!} />
        </Section>
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
                    <a href={href} target="_blank" rel="noreferrer" className={`break-all ${linkClass}`}>
                      {reference}
                    </a>
                  ) : (
                    <span className="break-all text-neutral-600 dark:text-neutral-400">{reference}</span>
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
          <summary className="cursor-pointer text-sm text-neutral-500 hover:text-neutral-800 dark:hover:text-neutral-200">Show exact raw JSON</summary>
          <div className="mt-2"><CodeBlock text={JSON.stringify(occurrence.raw, null, 2)} /></div>
        </details>
      </Section>
    </Page>
  );
}
