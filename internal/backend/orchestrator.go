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
	log      *slog.Logger

	pollInterval time.Duration
	maxPolls     int
}

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

	if err := o.store.MarkComplete(ctx, scanID, status.NucleiVersion, status.TemplatesCommit); err != nil {
		log.Error("mark complete", "err", err)
	}
	log.Info("scan complete", "findings", status.FindingCount)
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

	sc := bufio.NewScanner(reader)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // findings can be large
	n := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var f types.NucleiFinding
		if err := json.Unmarshal(line, &f); err != nil {
			o.log.Warn("skip unparseable finding line", "scan_id", scanID, "err", err)
			continue
		}
		// Copy the line: bufio.Scanner reuses its buffer on the next Scan.
		rawLine := make([]byte, len(line))
		copy(rawLine, line)
		if err := o.store.IngestFinding(ctx, scanID, targetID, f, rawLine); err != nil {
			return err
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read results stream: %w", err)
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
	if err := o.store.MarkFailed(ctx, scanID, reason); err != nil {
		o.log.Error("mark failed", "scan_id", scanID, "err", err)
	}
}
