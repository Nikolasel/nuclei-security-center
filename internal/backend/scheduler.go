package backend

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// cronParser accepts standard 5-field crontab syntax plus the @hourly/@daily/…
// and "@every <duration>" descriptors. We use it only to parse expressions and
// compute the next fire time — Postgres remains the source of truth for which
// schedules exist and when they next run.
var cronParser = cron.NewParser(
	cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
)

// parseCron validates a cron expression, returning its compiled schedule.
func parseCron(spec string) (cron.Schedule, error) {
	return cronParser.Parse(spec)
}

// nextRun returns the next fire time of a cron expression strictly after `after`.
func nextRun(spec string, after time.Time) (time.Time, error) {
	sched, err := parseCron(spec)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(after), nil
}

// Scheduler is the backend ticker that dispatches due schedules. It runs a
// single goroutine that wakes on an interval, claims schedules whose next_run_at
// has arrived, dispatches each through the orchestrator, and advances the
// schedule's next fire time. A single backend instance owns scheduling for the
// MVP (like the rest of the orchestrator); the DB stays the source of truth so a
// restart resumes cleanly and a schedule missed while down fires once on the
// next tick, then reschedules forward.
type Scheduler struct {
	store    *store.Store
	srv      *Server
	log      *slog.Logger
	interval time.Duration
}

// NewScheduler wires the ticker. The Server is reused for its config→spec
// resolution so scheduled and ad-hoc scans dispatch from identical stored config.
func NewScheduler(st *store.Store, srv *Server, log *slog.Logger) *Scheduler {
	return &Scheduler{
		store:    st,
		srv:      srv,
		log:      log.With("component", "scheduler"),
		interval: time.Minute, // cron's finest granularity is one minute
	}
}

// Start launches the ticker until ctx is cancelled. It runs one tick immediately
// so a schedule already due at boot doesn't wait a full interval.
func (s *Scheduler) Start(ctx context.Context) {
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

// maxDispatchPerTick caps how many schedules one tick dispatches, so a large due
// set (e.g. many schedules all cron'd to the same minute) can't produce an
// unbounded dispatch burst against the scanner node (CWE-770). Undispatched due
// schedules keep their past next_run_at and are simply re-selected next tick.
const maxDispatchPerTick = 20

// tick dispatches the currently-due schedules, up to maxDispatchPerTick. Ticks
// never overlap (one goroutine, synchronous), so a schedule can't be
// double-dispatched within a tick.
func (s *Scheduler) tick(ctx context.Context) {
	now := time.Now()
	due, err := s.store.DueSchedules(ctx, now)
	if err != nil {
		s.log.Error("list due schedules", "err", err)
		return
	}
	if len(due) > maxDispatchPerTick {
		s.log.Warn("due schedules exceed the per-tick cap; deferring the remainder to the next tick",
			"due", len(due), "cap", maxDispatchPerTick)
		due = capDueSchedules(due, maxDispatchPerTick)
	}
	for _, sc := range due {
		s.dispatch(ctx, sc, now)
	}
}

// capDueSchedules returns at most max schedules from due, preserving order (the
// store returns them ordered by next_run_at, so the most-overdue go first).
func capDueSchedules(due []store.Schedule, max int) []store.Schedule {
	if len(due) > max {
		return due[:max]
	}
	return due
}

// dispatch runs one schedule and advances its next fire time. Even on failure the
// schedule is rescheduled forward so a single broken run doesn't wedge the ticker
// into re-dispatching every tick.
func (s *Scheduler) dispatch(ctx context.Context, sc store.Schedule, now time.Time) {
	log := s.log.With("schedule_id", sc.ID, "schedule", sc.Name)

	next, err := nextRun(sc.Cron, now)
	if err != nil {
		// A bad cron would otherwise be re-selected every tick; disable it.
		log.Error("invalid cron on due schedule; disabling", "cron", sc.Cron, "err", err)
		sc.Enabled = false
		sc.NextRunAt = nil
		if _, uerr := s.store.UpdateSchedule(ctx, sc.ID, sc); uerr != nil {
			log.Error("disable broken schedule", "err", uerr)
		}
		return
	}

	scanID := ""
	spec, link, err := s.srv.resolvePolicySpec(ctx, sc.ScanPolicyID, sc.TargetID)
	if err != nil {
		log.Error("resolve schedule scan policy", "err", err)
	} else {
		link.Source = "schedule"
		link.ScheduleID = sc.ID
		scanID, err = s.srv.orch.Submit(ctx, spec, link)
		if err != nil {
			log.Error("dispatch scheduled scan", "err", err)
		} else {
			logSystemAudit(ctx, log, eventScanDispatched, "schedule.run", "scan", scanID,
				slog.String("scan_policy_id", link.ScanPolicyID),
				slog.String("target_id", link.TargetID),
				slog.String("scan_id", scanID),
			)
			log.Info("scheduled scan dispatched", "scan_id", scanID, "next_run", next)
		}
	}

	if err := s.store.RecordScheduleRun(ctx, sc.ID, scanID, now, next); err != nil {
		log.Error("record schedule run", "err", err)
	}
}

// scheduleNextRun computes a schedule's next_run_at: the next cron fire time when
// enabled, or nil when disabled (so the ticker's due-query skips it). Used by the
// create/update handlers.
func scheduleNextRun(cronSpec string, enabled bool, from time.Time) (*time.Time, error) {
	if !enabled {
		return nil, nil
	}
	next, err := nextRun(cronSpec, from)
	if err != nil {
		return nil, fmt.Errorf("cron %q: %w", cronSpec, err)
	}
	return &next, nil
}
