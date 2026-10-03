import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Download } from "lucide-react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  scanBundleExportUrl,
  scanLogUrl,
  scanRawUrl,
  type CoverageOrigin,
  type EndpointCoverage,
} from "../api";
import { hasRole, useMe } from "../auth";
import { ScanFindingsView } from "../components/ScanFindingsView";
import {
  Alert,
  Badge,
  Button,
  DescriptionList,
  ErrorText,
  linkClass,
  menuContentClass,
  menuItemClass,
  menuSeparatorClass,
  Meta,
  Muted,
  Page,
  PageHeader,
  ProgressBar,
  Section,
  Spinner,
  StateBadge,
  Tag,
  useConfirm,
} from "../components/ui";
import { formatDuration, scanEtaSeconds } from "../util";

export function ScanDetailPage() {
  const { id = "" } = useParams();
  const me = useMe();
  const canCancel = hasRole(me.data ?? undefined, "operator");
  const qc = useQueryClient();
  const confirm = useConfirm();

  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
    refetchInterval: (q) => {
      const s = q.state.data?.state;
      return s === "queued" || s === "running" ? 2000 : false;
    },
  });

  const cancel = useMutation({
    mutationFn: () => api.cancelScan(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scan", id] });
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const state = scan.data?.state;
  const active = state === "queued" || state === "running";
  // Terminal states: findings (if any were ingested) are shown; a cancelled scan
  // typically has none since ingest only runs on successful completion.
  const done = state === "complete" || state === "failed" || state === "cancelled";

  const short = id.slice(0, 8);
  const d = scan.data;

  return (
    <Page>
      <PageHeader
        back={{ label: "Scans", to: "/scans" }}
        title={<span className="font-mono">{short}</span>}
        badges={d && <StateBadge state={d.state} />}
        actions={
          <>
            {canCancel && active && (
              <Button
                variant="danger-ghost"
                disabled={cancel.isPending}
                onClick={async () => {
                  if (
                    await confirm({
                      title: `Stop scan ${short}?`,
                      description: "The scanner node cancels the run. Results collected so far are not ingested.",
                      confirmLabel: "Stop scan",
                    })
                  )
                    cancel.mutate();
                }}
              >
                Stop scan
              </Button>
            )}
            <DownloadMenu id={id} hasRaw={!!d?.has_raw} hasLog={!!d?.has_log} />
          </>
        }
      />

      {cancel.isError && <ErrorText error={cancel.error} />}

      {scan.isLoading ? (
        <Spinner />
      ) : scan.isError ? (
        <ErrorText error={scan.error} />
      ) : (
        scan.data && (
          <Section title="Run">
            <DescriptionList columns={4}>
              <Meta label="Target">
                {scan.data.target_name ? (
                  <>
                    <OptionalLink to={scan.data.target_id ? "/targets" : undefined}>{scan.data.target_name}</OptionalLink>
                    {scan.data.target_host_count ? (
                      <span className="text-neutral-400">
                        {" "}
                        ({scan.data.target_host_count} host{scan.data.target_host_count === 1 ? "" : "s"})
                      </span>
                    ) : null}
                  </>
                ) : (
                  <Muted>ad-hoc</Muted>
                )}
              </Meta>
              <Meta label="Scanner node">
                {scan.data.node_name ? (
                  <OptionalLink to={scan.data.node_id ? "/nodes" : undefined}>{scan.data.node_name}</OptionalLink>
                ) : (
                  <Muted />
                )}
              </Meta>
              <Meta label="Scan policy">
                {scan.data.scan_policy_name ? (
                  <OptionalLink to={scan.data.scan_policy_id ? "/scan-policies" : undefined}>
                    {scan.data.scan_policy_name}
                  </OptionalLink>
                ) : (
                  <Muted>Default</Muted>
                )}
              </Meta>
              <Meta label="Template set">
                {scan.data.template_set_name ? (
                  <OptionalLink to={scan.data.template_set_id ? "/template-sets" : undefined}>
                    {scan.data.template_set_name}
                  </OptionalLink>
                ) : (
                  <Muted />
                )}
              </Meta>
              <Meta label="Created">{new Date(scan.data.created_at).toLocaleString()}</Meta>
              <Meta label="Finished">
                {scan.data.finished_at ? new Date(scan.data.finished_at).toLocaleString() : <Muted />}
              </Meta>
              <Meta label="Nuclei">
                <span className="font-mono text-xs">{scan.data.nuclei_version || "—"}</span>
              </Meta>
            </DescriptionList>
            {/* Discovery phase (naabu, #86): no clean percentage, so an animated
                bar with the live per-host tally. The host count is naabu's
                host-discovery probe result ("responding", not "alive"): on a NAT'd
                dev network — Docker Desktop — every address answers, so the
                authoritative narrowed set is the "Discovered endpoints" list below,
                sourced from naabu's JSON rather than this live tally. */}
            {scan.data.state === "running" && scan.data.progress?.phase === "discovering" && (
              <div className="mt-4">
                <ProgressBar percent={0} indeterminate label="discovering…" />
                <p className="mt-1 text-xs text-neutral-500">
                  Discovering live hosts &amp; ports (naabu) · {scan.data.progress.disc_hosts ?? 0}{" "}
                  {(scan.data.progress.disc_hosts ?? 0) === 1 ? "host" : "hosts"} responding ·{" "}
                  {scan.data.progress.disc_ports ?? 0}{" "}
                  {(scan.data.progress.disc_ports ?? 0) === 1 ? "open port" : "open ports"} so far
                </p>
              </div>
            )}
            {/* Scanning phase (Nuclei): request-based percentage, stats shown
                per-target (#86) rather than as one overall counter. */}
            {scan.data.state === "running" &&
              scan.data.progress &&
              scan.data.progress.phase !== "discovering" && (
                <div className="mt-4">
                  <ProgressBar percent={scan.data.progress.percent} />
                  <p className="mt-1 text-xs text-neutral-500">
                    {(() => {
                      const p = scan.data.progress;
                      const done = p.requests ?? 0;
                      const total = p.total ?? 0;
                      // Nuclei reports only OVERALL request counts, not per-target
                      // progress — it interleaves templates across all targets rather
                      // than finishing one before the next. So show the real overall
                      // numbers, and translate the completion fraction into an
                      // ESTIMATE of targets done (~frac × count) rather than faking a
                      // per-target request figure by dividing the total. When discovery
                      // ran, the target count is the authoritative discovered-endpoint
                      // count (stable, and matches the "N ports on M hosts" line below);
                      // Nuclei's own "hosts" stat counts distinct hosts and fluctuates.
                      // Without discovery, fall back to that host count.
                      const discovered = scan.data.discovered_targets?.length ?? 0;
                      const count = discovered > 0 ? discovered : (p.hosts ?? 0);
                      const unit = discovered > 0 ? "endpoint" : "host";
                      const frac = total > 0 ? done / total : (p.percent ?? 0) / 100;
                      const estDone = Math.min(count, Math.round(frac * count));
                      const summary =
                        count > 0
                          ? `${done.toLocaleString()} / ${total.toLocaleString()} requests · ~${estDone} of ${count} ${unit}${count === 1 ? "" : "s"} scanned`
                          : `${done.toLocaleString()} / ${total.toLocaleString()} requests`;
                      const elapsed = (Date.now() - new Date(scan.data.created_at).getTime()) / 1000;
                      const eta = scanEtaSeconds(p, elapsed);
                      return (
                        <>
                          {summary}
                          {p.rps ? ` · ${p.rps} rps` : ""} ·{" "}
                          {eta != null ? `${formatDuration(eta)} remaining` : "estimating…"}
                        </>
                      );
                    })()}
                  </p>
                </div>
              )}
            {scan.data.state === "running" && !scan.data.progress && (
              <p className="mt-4 text-xs text-neutral-400">Waiting for progress from the scanner…</p>
            )}
            {scan.data.error && (
              <Alert tone="danger" title="Scan failed" className="mt-4">
                <span className="whitespace-pre-wrap">{scan.data.error}</span>
              </Alert>
            )}
            {scan.data.skipped_finding_count > 0 && (
              <Alert tone="warning" className="mt-4">
                {scan.data.skipped_finding_count.toLocaleString()}{" "}malformed finding{" "}
                {scan.data.skipped_finding_count === 1 ? "record was" : "records were"} skipped during ingest;
                indexed results are partial; absent findings cannot be auto-mitigated from this scan.
                Operational ingest failures remain scan-fatal.
              </Alert>
            )}
            {scan.data.discovered_targets && scan.data.discovered_targets.length > 0 && (
              <DiscoveredEndpoints targets={scan.data.discovered_targets} />
            )}
            {scan.data.state !== "running" && (
              <CoveredEndpoints
                endpoints={scan.data.covered_endpoints}
                warning={scan.data.coverage_warning}
                origin={scan.data.coverage_origin}
              />
            )}
          </Section>
        )
      )}

      {!done ? (
        <p className="text-sm text-neutral-500">Findings appear here once the scan finishes.</p>
      ) : (
        <ScanFindingsView scanId={id} />
      )}
    </Page>
  );
}

/** OptionalLink renders a link when the referenced record still exists. */
function OptionalLink({ to, children }: { to?: string; children: ReactNode }) {
  return to ? (
    <Link to={to} className={linkClass}>
      {children}
    </Link>
  ) : (
    <>{children}</>
  );
}

/** DownloadMenu groups the scan's archived artifacts behind one header button. */
function DownloadMenu({ id, hasRaw, hasLog }: { id: string; hasRaw: boolean; hasLog: boolean }) {
  const item = (href: string, label: string, title?: string) => (
    <DropdownMenu.Item asChild>
      <a href={href} title={title} className={menuItemClass}>
        {label}
      </a>
    </DropdownMenu.Item>
  );
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button>
          <Download className="h-4 w-4" aria-hidden />
          Download
          <ChevronDown className="h-4 w-4 text-neutral-400" aria-hidden />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" sideOffset={4} className={menuContentClass}>
          {hasRaw && item(scanRawUrl(id), "Raw output (JSONL)")}
          {hasLog && item(scanLogUrl(id), "Execution log")}
          {(hasRaw || hasLog) && <DropdownMenu.Separator className={menuSeparatorClass} />}
          {item(
            scanBundleExportUrl(id, "zip"),
            "Scan bundle (zip)",
            "Scan record, resolved config and every occurrence as preserved raw JSON — the destination re-derives its own finding lifecycle (#136)",
          )}
          {item(scanBundleExportUrl(id), "Scan bundle (JSON)", "Same bundle as readable JSON (#136)")}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

// CoveredEndpoints is the durable lifecycle evidence introduced by #91. Keep
// "unknown" distinct from a known empty trace: old scans must fail closed, while
// a completed scan that reached nothing has an explicit, explainable result.
function CoveredEndpoints({
  endpoints,
  warning,
  origin,
}: {
  endpoints?: EndpointCoverage[] | null;
  warning?: string;
  origin?: CoverageOrigin;
}) {
  if (endpoints == null) {
    return (
      <div className="mt-5 space-y-2">
        <CoverageSource origin={origin} />
        <Alert tone="warning" title="Endpoint coverage unavailable">
          This scan cannot mark absent findings as mitigated.
          {warning && <p className="mt-1">{warning}</p>}
        </Alert>
      </div>
    );
  }
  const visibleEndpoints = endpoints.slice(0, 500);
  return (
    <div className="mt-5">
      <CoverageSource origin={origin} />
      <p className="text-xs font-medium text-neutral-500">
        Template/endpoint checks completed · {endpoints.length.toLocaleString()}{" "}
        {endpoints.length === 1 ? "pair" : "pairs"}
      </p>
      {warning && (
        <Alert tone="warning" className="mt-2">
          {warning}
        </Alert>
      )}
      {endpoints.length === 0 ? (
        <p className="mt-1 text-xs text-neutral-400">
          No template/endpoint pair completed a successful request.
        </p>
      ) : (
        <div className="mt-2 flex max-h-40 flex-wrap gap-1 overflow-y-auto">
          {visibleEndpoints.map((pair) => (
            <Tag key={`${pair.template_id}\u001f${pair.endpoint}`} mono>
              {pair.template_id} · {pair.endpoint}
            </Tag>
          ))}
          {endpoints.length > visibleEndpoints.length && (
            <span className="px-2 py-1 text-xs text-neutral-400">
              +{(endpoints.length - visibleEndpoints.length).toLocaleString()} more
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function coverageSource(origin?: CoverageOrigin): { label: string; tone: "success" | "warning" } {
  switch (origin) {
    case "node":
      return { label: "scanner node", tone: "success" };
    case "import_trusted":
      return { label: "trusted imported bundle · operator opt-in", tone: "warning" };
    case "import_untrusted":
      return { label: "untrusted imported bundle · not mitigation evidence", tone: "warning" };
    default:
      return { label: "unknown source · not mitigation evidence", tone: "warning" };
  }
}

function CoverageSource({ origin }: { origin?: CoverageOrigin }) {
  const source = coverageSource(origin);
  return (
    <p className="mb-2 text-xs text-neutral-500">
      Coverage source: <Badge tone={source.tone}>{source.label}</Badge>
    </p>
  );
}

// DiscoveredEndpoints lists the host:port pairs the naabu pre-pass narrowed the
// target to (#86), grouped by host, so it's clear which endpoints Nuclei actually
// scanned. Shown whenever discovery ran (live during the scanning phase, and
// persisted after completion).
function DiscoveredEndpoints({ targets }: { targets: string[] }) {
  const groups = groupEndpoints(targets);
  const portCount = targets.length;
  return (
    <div className="mt-5">
      <p className="text-xs font-medium text-neutral-500">
        Discovered endpoints (naabu) · {portCount} {portCount === 1 ? "port" : "ports"} on {groups.length}{" "}
        {groups.length === 1 ? "host" : "hosts"}
      </p>
      <div className="mt-2 max-h-60 space-y-1 overflow-y-auto">
        {groups.map((g) => (
          <div key={g.host} className="flex flex-wrap items-baseline gap-x-2 text-xs">
            <span className="font-mono text-neutral-700 dark:text-neutral-300">{g.host}</span>
            <span className="font-mono text-neutral-500">{g.ports.join(", ")}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// groupEndpoints turns a flat host:port list into per-host port groups. It splits
// on the LAST colon so IPv6 literals ("[::1]:80") keep their bracketed host.
function groupEndpoints(targets: string[]): { host: string; ports: string[] }[] {
  const map = new Map<string, string[]>();
  for (const t of targets) {
    const idx = t.lastIndexOf(":");
    const host = idx > 0 ? t.slice(0, idx) : t;
    const port = idx > 0 ? t.slice(idx + 1) : "";
    const ports = map.get(host) ?? [];
    if (port) ports.push(port);
    map.set(host, ports);
  }
  return [...map.entries()].map(([host, ports]) => ({ host, ports }));
}
