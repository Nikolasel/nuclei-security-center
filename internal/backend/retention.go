package backend

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Scan retention (#95). A single-goroutine ticker that periodically deletes
// scans older than an admin-configured window, reusing the existing per-scan
// delete primitive (store.DeleteScan) rather than inventing a new one. It mirrors
// the Scheduler's shape: Postgres is the source of truth for what's due, a
// per-tick cap bounds the burst, and the policy is read fresh each tick so an
// admin edit takes effect without a restart.
type RetentionSweeper struct {
	store    *store.Store
	archiver ObjectStore // nil when object storage is not configured
	log      *slog.Logger
	interval time.Duration
}

// NewRetentionSweeper wires the sweeper. archiver may be nil (archived objects
// simply aren't purged — the DB row is still deleted).
func NewRetentionSweeper(st *store.Store, archiver ObjectStore, interval time.Duration, log *slog.Logger) *RetentionSweeper {
	if interval <= 0 {
		interval = time.Hour
	}
	return &RetentionSweeper{
		store:    st,
		archiver: archiver,
		log:      log.With("component", "retention"),
		interval: interval,
	}
}

// maxRetentionDeletePerTick caps how many scans one sweep deletes, so a large
// backlog (e.g. retention first enabled against years of history) can't produce
// an unbounded delete burst in a single pass (CWE-770). The remainder is picked
// up on the next tick.
const maxRetentionDeletePerTick = 100

// Start launches the ticker until ctx is cancelled. It runs one tick immediately
// so a backend that boots with retention already configured doesn't wait a full
// interval before the first sweep.
func (s *RetentionSweeper) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		s.tick(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.tick(ctx)
			}
		}
	}()
}

// tick reads the current policy and, when retention is active, deletes the due
// scans up to the per-tick cap. Ticks never overlap (one goroutine, synchronous).
func (s *RetentionSweeper) tick(ctx context.Context) {
	settings, err := s.store.GetAppSettings(ctx)
	if err != nil {
		s.log.Error("load app settings", "err", err)
		return
	}
	if !settings.RetentionActive() {
		return
	}
	cutoff := time.Now().Add(-time.Duration(*settings.ScanRetentionDays) * 24 * time.Hour)
	ids, err := s.store.ScansForRetention(ctx, cutoff, settings.RetentionIncludeAdhoc, maxRetentionDeletePerTick)
	if err != nil {
		s.log.Error("list scans for retention", "err", err)
		return
	}
	if len(ids) == 0 {
		return
	}
	s.log.Info("retention sweep starting", "retention_days", *settings.ScanRetentionDays,
		"include_adhoc", settings.RetentionIncludeAdhoc,
		"cutoff", cutoff.UTC().Format(time.RFC3339), "candidates", len(ids))
	deleted := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if s.deleteScan(ctx, id) {
			deleted++
		}
	}
	s.log.Info("retention sweep complete", "deleted", deleted)
}

// deleteScan removes one scan and best-effort purges its archived objects,
// emitting a system audit event on success. It returns whether the row was
// deleted. A scan that raced into a non-deletable state (ErrConflict) or vanished
// (ErrNotFound) is skipped quietly — the next tick reconsiders the set.
func (s *RetentionSweeper) deleteScan(ctx context.Context, id string) bool {
	rawKey, logKey, err := s.store.DeleteScan(ctx, id)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
			// Became queued/running, or already gone — leave it for next time.
		default:
			s.log.Warn("retention: delete scan", "scan_id", id, "err", err)
		}
		return false
	}
	if s.archiver != nil {
		for _, key := range []string{rawKey, logKey} {
			if key == "" {
				continue
			}
			if err := s.archiver.Delete(ctx, key); err != nil {
				s.log.Warn("retention: purge archived object", "scan_id", id, "key", key, "err", err)
			}
		}
	}
	// Every mutation is audited (docs/ARCHITECTURE.md); a background delete has no
	// HTTP request, so it goes through the system-actor variant.
	logSystemAudit(ctx, s.log, eventScanDispatched, "scan.delete", "scan", id)
	s.log.Info("retention: deleted scan", "scan_id", id)
	return true
}
