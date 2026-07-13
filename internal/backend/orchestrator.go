package backend

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Orchestrator dispatches scans to a scanner node, polls to completion, then
// pulls and ingests the results. The backend is the system of record; the node
// is stateless. (Phase 0 targets a single node; a registry comes later.)
type Orchestrator struct {
	store    *store.Store
	client   *ScannerClient
	archiver ObjectStore // nil when object storage is not configured
	indexer  Indexer     // nil when no derived search index is configured (#21)
	log      *slog.Logger

	pollInterval time.Duration
	maxPolls     int
}

// SetIndexer wires a derived-search-index sync (#21). When set, a completed
// scan re-projects its target's findings into the index (best-effort).
func (o *Orchestrator) SetIndexer(idx Indexer) { o.indexer = idx }

// NewOrchestrator wires the store and scanner client together. archiver may be
// nil, in which case raw output is ingested but not archived.
func NewOrchestrator(st *store.Store, client *ScannerClient, archiver ObjectStore, log *slog.Logger) *Orchestrator {
	return &Orchestrator{
		store:        st,
		client:       client,
		archiver:     archiver,
		log:          log,
		pollInterval: 3 * time.Second,
		maxPolls:     600, // ~30 min ceiling at 3s
	}
}

// rawObjectKey is the bucket key under which a scan's verbatim out.jsonl lives.
func rawObjectKey(scanID string) string { return "scans/" + scanID + "/raw.jsonl" }

// Ingest quotas. The node/results stream is otherwise trusted for volume: a
// compromised node, or a target crafted to make Nuclei emit an enormous number
// of findings, could drive unbounded DB writes and temp-file growth. These cap
// the total bytes read and the findings ingested per scan (CWE-400/CWE-770).
const (
	maxResultsBytes    = 512 << 20 // 512 MiB total results-stream ceiling
	maxFindingsPerScan = 100_000   // per-scan finding-count ceiling
)

// scanFindingLines reads JSONL findings from r under a byte cap (maxBytes) and a
// count cap (maxCount), invoking emit for each parsed finding with a private
// copy of its raw line. Unparseable lines are skipped (counted, not fatal).
// Exceeding either cap returns an error after the work done so far, so a
// misbehaving stream aborts rather than consuming unbounded resources.
func scanFindingLines(r io.Reader, maxBytes int64, maxCount int, emit func(types.NucleiFinding, []byte) error) (ingested, skipped int, err error) {
	// +1 so we can distinguish "exactly at the cap" from "over the cap".
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // findings can be large
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if ingested >= maxCount {
			return ingested, skipped, fmt.Errorf("results exceeded the %d-finding cap", maxCount)
		}
		var f types.NucleiFinding
		if json.Unmarshal(line, &f) != nil {
			skipped++
			continue
		}
		// Copy the line: bufio.Scanner reuses its buffer on the next Scan.
		rawLine := make([]byte, len(line))
		copy(rawLine, line)
		if e := emit(f, rawLine); e != nil {
			return ingested, skipped, e
		}
		ingested++
	}
	if e := sc.Err(); e != nil {
		return ingested, skipped, fmt.Errorf("read results stream: %w", e)
	}
	if limited.N <= 0 {
		return ingested, skipped, fmt.Errorf("results stream exceeded the %d-byte cap", maxBytes)
	}
	return ingested, skipped, nil
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
	// Detached from the request context; give the whole run a generous ceiling.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	log := o.log.With("scan_id", scanID)

	nodeScanID, err := o.client.StartScan(ctx, spec)
	if err != nil {
		o.failScan(ctx, scanID, "dispatch: "+err.Error())
		return
	}
	if err := o.store.MarkRunning(ctx, scanID, nodeScanID); err != nil {
		log.Error("mark running", "err", err)
	}
	log.Info("scan dispatched", "node_scan_id", nodeScanID)

	status, err := o.pollToDone(ctx, nodeScanID)
	if err != nil {
		o.failScan(ctx, scanID, err.Error())
		return
	}
	if status.State == types.ScanFailed {
		o.failScan(ctx, scanID, "node reported failure: "+status.Error)
		return
	}

	if err := o.ingest(ctx, scanID, targetID, nodeScanID); err != nil {
		o.failScan(ctx, scanID, "ingest: "+err.Error())
		return
	}

	err = retryWrite(ctx, terminalWriteAttempts, terminalWriteDelay, func() error {
		return o.store.MarkComplete(ctx, scanID, status.NucleiVersion, status.TemplatesCommit)
	})
	if err != nil {
		log.Error("mark complete", "err", err)
	}
	log.Info("scan complete", "findings", status.FindingCount)

	// Sync the derived search index for this target (#21). Best-effort: Postgres
	// is the system of record, so an index blip must not fail the scan.
	if o.indexer != nil {
		if err := o.indexer.ReindexTarget(ctx, targetID); err != nil {
			log.Warn("reindex target to search index", "err", err)
		}
	}
}

// pollToDone polls the node until the scan reaches a terminal state.
func (o *Orchestrator) pollToDone(ctx context.Context, nodeScanID string) (types.ScanStatus, error) {
	for i := 0; i < o.maxPolls; i++ {
		select {
		case <-ctx.Done():
			return types.ScanStatus{}, ctx.Err()
		case <-time.After(o.pollInterval):
		}
		st, err := o.client.Status(ctx, nodeScanID)
		if err != nil {
			// Transient node/network blips shouldn't kill the run; keep polling.
			o.log.Warn("poll status failed", "node_scan_id", nodeScanID, "err", err)
			continue
		}
		if st.State == types.ScanComplete || st.State == types.ScanFailed {
			return st, nil
		}
	}
	return types.ScanStatus{}, fmt.Errorf("scan did not finish within poll budget")
}

// ingest streams the node's JSONL results and writes each finding to Postgres.
// targetID scopes the deduplicated lifecycle entity (empty for ad-hoc scans).
// When an archiver is configured, the verbatim stream is tee'd to a temp file
// and uploaded to object storage after a successful ingest (see archiveRaw).
func (o *Orchestrator) ingest(ctx context.Context, scanID, targetID, nodeScanID string) error {
	body, err := o.client.Results(ctx, nodeScanID)
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

	n, skipped, err := scanFindingLines(reader, maxResultsBytes, maxFindingsPerScan,
		func(f types.NucleiFinding, rawLine []byte) error {
			return o.store.IngestFinding(ctx, scanID, targetID, f, rawLine)
		})
	if skipped > 0 {
		o.log.Warn("skipped unparseable finding lines", "scan_id", scanID, "skipped", skipped)
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

func (o *Orchestrator) failScan(ctx context.Context, scanID, reason string) {
	o.log.Error("scan failed", "scan_id", scanID, "reason", reason)
	err := retryWrite(ctx, terminalWriteAttempts, terminalWriteDelay, func() error {
		return o.store.MarkFailed(ctx, scanID, reason)
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
