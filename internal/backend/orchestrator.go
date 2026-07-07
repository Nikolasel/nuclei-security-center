package backend

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Orchestrator dispatches scans to a scanner node, polls to completion, then
// pulls and ingests the results. The backend is the system of record; the node
// is stateless. (Phase 0 targets a single node; a registry comes later.)
type Orchestrator struct {
	store  *store.Store
	client *ScannerClient
	log    *slog.Logger

	pollInterval time.Duration
	maxPolls     int
}

// NewOrchestrator wires the store and scanner client together.
func NewOrchestrator(st *store.Store, client *ScannerClient, log *slog.Logger) *Orchestrator {
	return &Orchestrator{
		store:        st,
		client:       client,
		log:          log,
		pollInterval: 3 * time.Second,
		maxPolls:     600, // ~30 min ceiling at 3s
	}
}

// Submit records a scan, then runs the dispatch/poll/ingest loop in the
// background. It returns the backend scan id immediately.
func (o *Orchestrator) Submit(ctx context.Context, spec types.ScanSpec) (string, error) {
	scanID, err := o.store.CreateScan(ctx, spec)
	if err != nil {
		return "", err
	}
	go o.run(scanID, spec)
	return scanID, nil
}

func (o *Orchestrator) run(scanID string, spec types.ScanSpec) {
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

	if err := o.ingest(ctx, scanID, nodeScanID); err != nil {
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
func (o *Orchestrator) ingest(ctx context.Context, scanID, nodeScanID string) error {
	body, err := o.client.Results(ctx, nodeScanID)
	if err != nil {
		return err
	}
	defer body.Close()

	sc := bufio.NewScanner(body)
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
		raw := make([]byte, len(line))
		copy(raw, line)
		if err := o.store.InsertFinding(ctx, scanID, f, raw); err != nil {
			return err
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read results stream: %w", err)
	}
	o.log.Info("ingested findings", "scan_id", scanID, "count", n)
	return nil
}

func (o *Orchestrator) failScan(ctx context.Context, scanID, reason string) {
	o.log.Error("scan failed", "scan_id", scanID, "reason", reason)
	if err := o.store.MarkFailed(ctx, scanID, reason); err != nil {
		o.log.Error("mark failed", "scan_id", scanID, "err", err)
	}
}
