package backend

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Orchestrator dispatches scans to a scanner node, polls to completion, then
// pulls and ingests the results. The backend is the system of record; the node
// is stateless. The scanner node is selected from the DB-backed registry (#22)
// by the target's CIDR; a single-node deployment routes every scan to the one
// catch-all node.
type Orchestrator struct {
	store       *store.Store
	archiver    ObjectStore          // nil when object storage is not configured
	health      *HealthMonitor       // nil disables health-aware dispatch
	distributor *TemplateDistributor // pre-dispatch catalog top-up (#85)
	log         *slog.Logger

	pollInterval time.Duration

	// progress caches the latest live progress per running scan (#66), refreshed
	// each poll. It is ephemeral by design — never persisted (invariant #4) — so
	// the API can render a progress bar without a node round-trip per request or
	// any new Postgres storage. Entries are removed when a scan ends.
	progressMu sync.Mutex
	progress   map[string]*types.ScanProgress
	// discovered caches the naabu-narrowed host:port list per running scan (#86),
	// so the UI can show discovered endpoints during the scanning phase, before the
	// list is persisted at completion. Also ephemeral; cleared when a scan ends.
	discovered map[string][]string
}

// NewOrchestrator wires the store together with the archiver and health monitor.
// Scanner nodes are resolved per scan from the store's registry. archiver may be
// nil (raw output is ingested but not archived); health may be nil (dispatch is
// not health-aware).
func NewOrchestrator(st *store.Store, archiver ObjectStore, health *HealthMonitor, log *slog.Logger) *Orchestrator {
	return &Orchestrator{
		store:        st,
		archiver:     archiver,
		health:       health,
		log:          log,
		pollInterval: 3 * time.Second,
		progress:     make(map[string]*types.ScanProgress),
		discovered:   make(map[string][]string),
	}
}

// SetTemplateDistributor enables pre-dispatch catalog top-up. It is wired once
// during backend startup before the HTTP server begins accepting scans.
func (o *Orchestrator) SetTemplateDistributor(d *TemplateDistributor) { o.distributor = d }

// Health exposes the node health monitor (nil when health polling is disabled).
func (o *Orchestrator) Health() *HealthMonitor { return o.health }

// clientForScan resolves the scanner node for a scan's targets from the registry
// and returns a client for it plus the node itself (for logging + recording which
// node ran the scan, #107). A spanning-node or no-node error propagates so run()
// can fail the scan before contacting anyone. If the resolved node is *known*
// unhealthy (polled and failed within the TTL), the scan fails fast with a clear
// error rather than dispatching into a black hole; a not-yet-polled node
// dispatches optimistically.
func (o *Orchestrator) clientForScan(ctx context.Context, targets []string) (*ScannerClient, store.ScannerNode, error) {
	node, err := o.store.SelectScannerNode(ctx, targets)
	if err != nil {
		return nil, store.ScannerNode{}, err
	}
	if o.health != nil {
		if h, known := o.health.Get(node.ID); known && !h.Healthy {
			return nil, store.ScannerNode{}, fmt.Errorf("matching scanner node %q is unhealthy (last seen %s)", node.Name, lastSeenText(h.LastSeen))
		}
	}
	client, err := clientForNode(node)
	if err != nil {
		return nil, store.ScannerNode{}, err
	}
	return client, node, nil
}

// lastSeenText renders a node's last-successful-poll time for an error message,
// distinguishing "never" from a timestamp.
func lastSeenText(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// Progress returns the latest cached live progress for a running scan, or nil
// when none is known (scan not running, or the node hasn't reported stats yet).
func (o *Orchestrator) Progress(scanID string) *types.ScanProgress {
	o.progressMu.Lock()
	defer o.progressMu.Unlock()
	return o.progress[scanID]
}

func (o *Orchestrator) setProgress(scanID string, p *types.ScanProgress) {
	if p == nil {
		return
	}
	o.progressMu.Lock()
	o.progress[scanID] = p
	o.progressMu.Unlock()
}

func (o *Orchestrator) clearProgress(scanID string) {
	o.progressMu.Lock()
	delete(o.progress, scanID)
	delete(o.discovered, scanID)
	o.progressMu.Unlock()
}

// Discovered returns the cached naabu-narrowed host:port list for a running scan
// (#86), or nil if none is known yet. Guarded by the same mutex as progress.
func (o *Orchestrator) Discovered(scanID string) []string {
	o.progressMu.Lock()
	defer o.progressMu.Unlock()
	return o.discovered[scanID]
}

func (o *Orchestrator) setDiscovered(scanID string, targets []string) {
	if len(targets) == 0 {
		return
	}
	o.progressMu.Lock()
	o.discovered[scanID] = targets
	o.progressMu.Unlock()
}

// rawObjectKey is the bucket key under which a scan's verbatim out.jsonl lives.
func rawObjectKey(scanID string) string { return "scans/" + scanID + "/raw.jsonl" }

// logObjectKey is the bucket key under which a scan's execution log (Nuclei's
// stdout/stderr, #94) lives. A separate object from rawObjectKey.
func logObjectKey(scanID string) string { return "scans/" + scanID + "/log.txt" }

// maxLogBytes caps how much of a scan's execution log is archived, so a
// misbehaving or compromised node can't stream an unbounded log into object
// storage (CWE-400), mirroring the results-stream ceiling.
const maxLogBytes = 128 << 20 // 128 MiB execution-log ceiling

// Ingest quotas. The node/results stream is otherwise trusted for volume: a
// compromised node, or a target crafted to make Nuclei emit an enormous number
// of findings, could drive unbounded DB writes and temp-file growth. These cap
// the total bytes read and the findings ingested per scan (CWE-400/CWE-770).
const (
	maxResultsBytes       = 512 << 20 // 512 MiB total results-stream ceiling
	maxFindingsPerScan    = 100_000   // per-scan finding-count ceiling
	maxFindingSkipDetails = 8         // bound diagnostic samples in logs
)

// scanFindingLines reads JSONL findings from r under a byte cap (maxBytes) and a
// count cap (maxCount), invoking emit for each parsed finding with a private
// copy of its raw line. Unparseable lines are skipped (counted, not fatal).
// Exceeding either cap returns an error after the work done so far, so a
// misbehaving stream aborts rather than consuming unbounded resources.
func scanFindingLines(r io.Reader, maxBytes int64, maxCount int, emit func(types.NucleiFinding, []byte) error) (ingested, skipped int, err error) {
	ingested, skipped, _, err = scanFindingLinesWithDetails(r, maxBytes, maxCount, emit)
	return ingested, skipped, err
}

// scanFindingLinesWithDetails is scanFindingLines plus a bounded set of
// non-sensitive line/reason samples for operator diagnostics. Only parse
// failures and store.FindingRecordError values are skipped; every other emit
// error is returned and remains scan-fatal.
func scanFindingLinesWithDetails(
	r io.Reader,
	maxBytes int64,
	maxCount int,
	emit func(types.NucleiFinding, []byte) error,
) (ingested, skipped int, details []string, err error) {
	// +1 so we can distinguish "exactly at the cap" from "over the cap".
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // findings can be large
	lineNumber := 0
	for sc.Scan() {
		lineNumber++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if ingested >= maxCount {
			return ingested, skipped, details, fmt.Errorf("results exceeded the %d-finding cap", maxCount)
		}
		var f types.NucleiFinding
		if e := json.Unmarshal(line, &f); e != nil {
			skipped++
			details = appendFindingSkipDetail(details, lineNumber, "parse: "+e.Error())
			continue
		}
		// Copy the line: bufio.Scanner reuses its buffer on the next Scan.
		rawLine := make([]byte, len(line))
		copy(rawLine, line)
		if e := emit(f, rawLine); e != nil {
			var recordErr *store.FindingRecordError
			if errors.As(e, &recordErr) {
				skipped++
				details = appendFindingSkipDetail(details, lineNumber, "record: "+recordErr.Stage())
				continue
			}
			return ingested, skipped, details, e
		}
		ingested++
	}
	if e := sc.Err(); e != nil {
		return ingested, skipped, details, fmt.Errorf("read results stream: %w", e)
	}
	if limited.N <= 0 {
		return ingested, skipped, details, fmt.Errorf("results stream exceeded the %d-byte cap", maxBytes)
	}
	return ingested, skipped, details, nil
}

func appendFindingSkipDetail(details []string, lineNumber int, reason string) []string {
	if len(details) >= maxFindingSkipDetails {
		return details
	}
	return append(details, fmt.Sprintf("line %d: %s", lineNumber, reason))
}

// Submit records a scan (optionally linked to the config it came from), then
// runs the dispatch/poll/ingest loop in the background. It returns the backend
// scan id immediately.
func (o *Orchestrator) Submit(ctx context.Context, spec types.ScanSpec, link store.ScanLink) (string, error) {
	scanID, err := o.store.CreateScan(ctx, spec, link)
	if err != nil {
		return "", err
	}
	go o.run(scanID, link.TargetID, spec)
	return scanID, nil
}

func (o *Orchestrator) run(scanID, targetID string, spec types.ScanSpec) {
	// Detached from the request context. The ceiling is derived from THIS scan's
	// timeouts (discovery + Nuclei run sequentially on the node), not a fixed value:
	// #86's discovery pre-pass adds its own budget on top of the Nuclei timeout, so a
	// fixed ceiling would abandon a scan the node is still legitimately running. The
	// poll budget must exceed the node's own max runtime so the node's specific
	// timeout error (e.g. "discovery timed out") wins over the generic give-up.
	pollWait := nodeRuntimeBudget(spec) + nodeOverhead
	ctx, cancel := context.WithTimeout(context.Background(), templateTopUpQueueBudget+pollWait+ingestTail)
	defer cancel()
	// Live progress is only meaningful while the scan runs; drop it at the end.
	defer o.clearProgress(scanID)

	log := o.log.With("scan_id", scanID)

	// Resolve the scanner node serving the scan's targets from the registry (#22).
	client, node, err := o.clientForScan(ctx, spec.Targets)
	if err != nil {
		// No node was contacted yet, so no version is known to record.
		o.failScan(ctx, scanID, "dispatch: "+err.Error(), "", "")
		return
	}
	log = log.With("node", node.Name)
	// Record which node was selected (#107), before contacting it — so the choice
	// is visible for triage even if the dispatch/run then fails.
	if err := o.store.SetScanNode(ctx, scanID, node.ID); err != nil {
		log.Warn("record scan node", "err", err)
	}

	if err := o.ensureTemplateBundle(ctx, client, node, spec); err != nil {
		o.failScan(ctx, scanID, "template top-up: "+err.Error(), "", spec.Templates.TemplatesCommit)
		return
	}

	nodeScanID, err := client.StartScan(ctx, spec)
	if err != nil {
		// No status response yet at this point -- nothing to record.
		o.failScan(ctx, scanID, "dispatch: "+err.Error(), "", "")
		return
	}
	if err := o.store.MarkRunning(ctx, scanID, nodeScanID); err != nil {
		log.Error("mark running", "err", err)
	}
	log.Info("scan dispatched", "node_scan_id", nodeScanID)

	status, err := o.pollToDone(ctx, client, scanID, nodeScanID, pollWait)
	if err != nil {
		// pollToDone returns a zero-value status on error, so there's genuinely
		// nothing to record here either.
		o.failScan(ctx, scanID, err.Error(), "", "")
		return
	}
	// The node reports its version before the scan even starts, so it's known
	// regardless of how the run ended. Record it unconditionally here, not just
	// in the failed/complete branches below: if an operator cancelled the scan,
	// store.CancelScan already flipped state to cancelled, and MarkFailed/
	// MarkComplete both refuse to touch an already-terminal row -- without this,
	// a cancelled scan silently never gets its nuclei_version recorded.
	if status.NucleiVersion != "" {
		if err := o.store.SetScanVersions(ctx, scanID, status.NucleiVersion, status.TemplatesCommit); err != nil {
			log.Warn("record scan versions", "err", err)
		}
	}
	// Persist the naabu-narrowed endpoint list (#86) unconditionally, like the
	// version: discovery completes before Nuclei, so it's known even if the Nuclei
	// run then failed/timed out, and the UI should show what was scanned either way.
	if err := o.store.SetScanDiscovered(ctx, scanID, status.DiscoveredTargets); err != nil {
		log.Warn("record discovered targets", "err", err)
	}
	// Persist exact template+endpoint request-trace coverage before
	// ingest/completion. MarkComplete advances only matching lifecycle evidence.
	if err := o.store.SetScanCoverage(ctx, scanID, status.CoveredEndpoints, status.CoverageWarning); err != nil {
		log.Warn("record endpoint coverage", "err", err)
	}
	// Archive the node's execution log regardless of outcome (it's most useful
	// on failure). pollToDone only returns on a terminal node state, so the log
	// is complete on the node by now. Best-effort, like the raw archive.
	o.archiveLog(ctx, client, scanID, nodeScanID)
	if status.State == types.ScanFailed {
		// The node reports its nuclei version before running the scan (see
		// Runner.run), so it's already known even though the run itself failed
		// (e.g. a timeout kill) -- worth keeping rather than discarding.
		// Nuclei also writes its JSONL output incrementally, so a killed run
		// still has whatever it found flushed to disk on the node -- ingest it
		// best-effort before recording the failure, so a large multi-host scan
		// that overruns its timeout doesn't lose every finding from the hosts
		// that did finish in time.
		if err := o.ingest(ctx, client, scanID, targetID, nodeScanID); err != nil {
			log.Warn("partial ingest after scan failure", "err", err)
		}
		o.failScan(ctx, scanID, "node reported failure: "+status.Error, status.NucleiVersion, status.TemplatesCommit)
		return
	}

	if err := o.ingest(ctx, client, scanID, targetID, nodeScanID); err != nil {
		o.failScan(ctx, scanID, "ingest: "+err.Error(), status.NucleiVersion, status.TemplatesCommit)
		return
	}

	err = retryWrite(ctx, terminalWriteAttempts, terminalWriteDelay, func() error {
		return o.store.MarkComplete(ctx, scanID, status.NucleiVersion, status.TemplatesCommit)
	})
	if err != nil {
		log.Error("mark complete", "err", err)
	}
	log.Info("scan complete", "findings", status.FindingCount)
}

// ensureTemplateBundle tops up a stale node before scan dispatch. Staleness is
// deliberately belt-and-suspenders: selected-template timestamps catch catalog
// edits since the last successful push, while a fresh capabilities call catches
// reality drift (for example a wiped node volume). A busy node is waited out;
// its activation endpoint also returns 409 on the race between the DB idle check
// and the push.
func (o *Orchestrator) ensureTemplateBundle(
	ctx context.Context,
	client *ScannerClient,
	node store.ScannerNode,
	spec types.ScanSpec,
) error {
	if len(spec.Templates.TemplateIDs) == 0 || spec.Templates.TemplatesCommit == "" {
		return errors.New("scan spec has no explicit template selection")
	}

	staleByTime := node.TemplatesSyncedAt == nil
	if node.TemplatesSyncedAt != nil {
		var err error
		staleByTime, err = o.store.TemplatesUpdatedAfter(
			ctx,
			spec.Templates.TemplateIDs,
			*node.TemplatesSyncedAt,
		)
		if err != nil {
			return err
		}
	}
	caps, err := client.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("read node capabilities: %w", err)
	}
	if !staleByTime && caps.TemplatesCommit == spec.Templates.TemplatesCommit {
		return nil
	}
	if o.distributor == nil {
		return errors.New("template distributor is unavailable")
	}

	for {
		busy, err := o.store.NodeHasActiveScan(ctx, node.ID)
		if err != nil {
			return fmt.Errorf("check node busy: %w", err)
		}
		if busy {
			if err := waitForTemplateTopUp(ctx); err != nil {
				return err
			}
			continue
		}
		status, err := o.distributor.SyncNode(ctx, node.ID)
		if errors.Is(err, ErrScannerBusy) {
			if err := waitForTemplateTopUp(ctx); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("push catalog: %w", err)
		}
		if status.TemplatesCommit != spec.Templates.TemplatesCommit {
			return fmt.Errorf(
				"catalog changed during dispatch: scan resolved %q, node activated %q; retry the scan",
				spec.Templates.TemplatesCommit, status.TemplatesCommit,
			)
		}
		return nil
	}
}

func waitForTemplateTopUp(ctx context.Context) error {
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("wait for scanner node to become idle: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// Wall-clock a scan spends outside its discovery/Nuclei timeouts. nodeOverhead is
// on the node before the timed work plus catalog top-up, dispatch, and
// poll-interval slack; ingestTail is backend-side
// headroom to stream and persist results after the node reports complete.
const (
	templateTopUpQueueBudget = 45 * time.Minute
	nodeOverhead             = 8 * time.Minute
	ingestTail               = 5 * time.Minute
)

// nodeRuntimeBudget is the longest the node may legitimately spend on a scan: the
// discovery pre-pass (#86) and the Nuclei run execute sequentially, each capped by
// its own timeout. It mirrors the node's built-in defaults (runner.go / discover.go)
// when the spec leaves a timeout at 0 ("use the default"), so the backend's poll
// budget always covers what the node could actually take.
func nodeRuntimeBudget(spec types.ScanSpec) time.Duration {
	nuclei := time.Duration(spec.Options.TimeoutSec) * time.Second
	if nuclei <= 0 {
		nuclei = 30 * time.Minute // runner.go's fallback
	}
	var discovery time.Duration
	if d := spec.Options.Discovery; d != nil && d.Enabled {
		discovery = time.Duration(d.TimeoutSec) * time.Second
		if discovery <= 0 {
			discovery = 5 * time.Minute // discover.go's defaultDiscoveryTimeout
		}
	}
	return nuclei + discovery
}

// pollToDone polls the given node until the scan reaches a terminal state or the
// budget elapses, caching the live progress from each poll under scanID so the API
// can render a progress bar. budget is this scan's derived ceiling (see
// nodeRuntimeBudget); it is intentionally larger than the node's own timeouts so a
// scan that overruns fails with the node's specific error, not this generic one.
func (o *Orchestrator) pollToDone(ctx context.Context, client *ScannerClient, scanID, nodeScanID string, budget time.Duration) (types.ScanStatus, error) {
	maxPolls := int(budget / o.pollInterval)
	for i := 0; i < maxPolls; i++ {
		select {
		case <-ctx.Done():
			return types.ScanStatus{}, ctx.Err()
		case <-time.After(o.pollInterval):
		}
		st, err := client.Status(ctx, nodeScanID)
		if err != nil {
			// Transient node/network blips shouldn't kill the run; keep polling.
			o.log.Warn("poll status failed", "node_scan_id", nodeScanID, "err", err)
			continue
		}
		o.setProgress(scanID, st.Progress)
		o.setDiscovered(scanID, st.DiscoveredTargets)
		if st.State == types.ScanComplete || st.State == types.ScanFailed {
			return st, nil
		}
	}
	return types.ScanStatus{}, fmt.Errorf("scan did not finish within poll budget (%s)", budget.Round(time.Minute))
}

// ingest streams the node's JSONL results and writes each finding to Postgres.
// targetID scopes the deduplicated lifecycle entity (empty for ad-hoc scans).
// When an archiver is configured, the verbatim stream is tee'd to a temp file
// and uploaded to object storage after a successful ingest (see archiveRaw).
func (o *Orchestrator) ingest(ctx context.Context, client *ScannerClient, scanID, targetID, nodeScanID string) error {
	body, err := client.Results(ctx, nodeScanID)
	if err != nil {
		return err
	}
	defer body.Close()

	// Tee the raw byte stream to a temp file so we can archive the exact output
	// the node produced — independent of whether every line parses.
	reader := io.Reader(body)
	var raw *os.File
	if o.archiver != nil {
		if raw, err = os.CreateTemp("", "nsc-raw-*.jsonl"); err != nil {
			o.log.Warn("raw archive: temp file, skipping archive", "scan_id", scanID, "err", err)
		} else {
			defer os.Remove(raw.Name())
			defer raw.Close()
			reader = io.TeeReader(body, raw)
		}
	}

	n, skipped, skipDetails, err := scanFindingLinesWithDetails(reader, maxResultsBytes, maxFindingsPerScan,
		func(f types.NucleiFinding, rawLine []byte) error {
			return o.store.IngestFinding(ctx, scanID, targetID, f, rawLine)
		})
	if skipped > 0 {
		o.log.Warn("skipped malformed finding records", "scan_id", scanID, "skipped", skipped, "samples", skipDetails)
		if persistErr := o.store.SetScanSkippedFindingCount(ctx, scanID, skipped); persistErr != nil {
			if err == nil {
				return fmt.Errorf("record skipped finding count: %w", persistErr)
			}
			o.log.Warn("record skipped finding count", "scan_id", scanID, "err", persistErr)
		}
	}
	if err != nil {
		return err
	}
	o.log.Info("ingested findings", "scan_id", scanID, "count", n)

	if raw != nil {
		o.archiveRaw(ctx, scanID, raw)
	}
	return nil
}

// archiveRaw uploads the tee'd raw output to object storage and records its key.
// It is best-effort: the projected findings are already the system of record, so
// a storage blip must not fail an otherwise-good scan — it's logged, not fatal.
func (o *Orchestrator) archiveRaw(ctx context.Context, scanID string, raw *os.File) {
	size, err := raw.Seek(0, io.SeekEnd)
	if err != nil {
		o.log.Warn("raw archive: size", "scan_id", scanID, "err", err)
		return
	}
	if _, err := raw.Seek(0, io.SeekStart); err != nil {
		o.log.Warn("raw archive: rewind", "scan_id", scanID, "err", err)
		return
	}
	key := rawObjectKey(scanID)
	if err := o.archiver.Put(ctx, key, raw, size, "application/x-ndjson"); err != nil {
		o.log.Warn("raw archive: upload", "scan_id", scanID, "err", err)
		return
	}
	if err := o.store.SetScanRawObject(ctx, scanID, key); err != nil {
		o.log.Warn("raw archive: record key", "scan_id", scanID, "err", err)
		return
	}
	o.log.Info("archived raw output", "scan_id", scanID, "key", key, "bytes", size)
}

// archiveLog pulls the scan's execution log from the node and uploads it to
// object storage under logObjectKey, recording the key. It is best-effort and a
// no-op when archiving is disabled: the log is a debugging convenience, never the
// system of record, so a fetch/storage error is logged, never fatal to the scan.
func (o *Orchestrator) archiveLog(ctx context.Context, client *ScannerClient, scanID, nodeScanID string) {
	if o.archiver == nil {
		return
	}
	body, err := client.Log(ctx, nodeScanID)
	if err != nil {
		o.log.Warn("log archive: fetch", "scan_id", scanID, "err", err)
		return
	}
	defer body.Close()
	key := logObjectKey(scanID)
	// size unknown (-1) → streamed upload; capped so a runaway log can't grow
	// storage without bound.
	if err := o.archiver.Put(ctx, key, io.LimitReader(body, maxLogBytes), -1, "text/plain; charset=utf-8"); err != nil {
		o.log.Warn("log archive: upload", "scan_id", scanID, "err", err)
		return
	}
	if err := o.store.SetScanLogObject(ctx, scanID, key); err != nil {
		o.log.Warn("log archive: record key", "scan_id", scanID, "err", err)
		return
	}
	o.log.Info("archived execution log", "scan_id", scanID, "key", key)
}

// SignalNodeCancel best-effort asks the scanner node to abort a running scan.
// The backend has already recorded state=cancelled (store.CancelScan is the
// authority), so a node that can't be reached only means the run keeps burning
// until its own timeout — never a correctness problem. Errors are logged, not
// returned.
func (o *Orchestrator) SignalNodeCancel(ctx context.Context, nodeScanID string) {
	if nodeScanID == "" {
		return // never dispatched (still queued) — nothing running on a node
	}
	// The node that ran a given scan isn't recoverable from the node scan id
	// alone, so broadcast the cancel to every registered node: the one running it
	// aborts, the rest 404 harmlessly. One node in a single-node deployment.
	nodes, err := o.store.ListScannerNodes(ctx)
	if err != nil {
		o.log.Warn("signal node cancel: list nodes", "node_scan_id", nodeScanID, "err", err)
		return
	}
	for _, n := range nodes {
		client, err := clientForNode(n)
		if err != nil {
			o.log.Warn("signal node cancel: build client", "node", n.Name, "err", err)
			continue
		}
		if err := client.Cancel(ctx, nodeScanID); err != nil {
			o.log.Warn("signal node cancel", "node", n.Name, "node_scan_id", nodeScanID, "err", err)
		}
	}
}

func (o *Orchestrator) failScan(ctx context.Context, scanID, reason, nucleiVersion, templatesCommit string) {
	o.log.Error("scan failed", "scan_id", scanID, "reason", reason)
	err := retryWrite(ctx, terminalWriteAttempts, terminalWriteDelay, func() error {
		return o.store.MarkFailed(ctx, scanID, reason, nucleiVersion, templatesCommit)
	})
	if err != nil {
		o.log.Error("mark failed", "scan_id", scanID, "err", err)
	}
}

// terminalWriteAttempts/terminalWriteDelay bound the retry of a scan's
// terminal-state write (MarkFailed/MarkComplete). A scan's outcome shouldn't
// be lost to a brief database blip (e.g. an Aurora auto-pause/resume cycle) —
// but a genuinely down database must not be retried forever, so orphaned
// scans are also swept on backend startup (see store.FailOrphanedScans).
const (
	terminalWriteAttempts = 5
	terminalWriteDelay    = 3 * time.Second
)

// retryWrite calls fn until it succeeds, ctx is done, or attempts is
// exhausted, waiting delay between tries. It returns fn's last error.
func retryWrite(ctx context.Context, attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
	}
	return err
}
