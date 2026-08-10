package backend

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	scs, err := s.store.ListSchedules(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if scs == nil {
		scs = []store.Schedule{}
	}
	writeJSON(w, http.StatusOK, scs)
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	// Default to enabled when the client omits the field (decode over the default).
	in := store.Schedule{Enabled: true}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validateSchedule(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	next, err := scheduleNextRun(in.Cron, in.Enabled, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.NextRunAt = next
	in.CreatedBy = identityFrom(r.Context()).Subject
	sc, err := s.store.CreateSchedule(r.Context(), in)
	if err != nil {
		s.writeScheduleErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sc)
}

func (s *Server) handleGetSchedule(w http.ResponseWriter, r *http.Request) {
	sc, err := s.store.GetSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) handleUpdateSchedule(w http.ResponseWriter, r *http.Request) {
	in := store.Schedule{Enabled: true}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validateSchedule(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Recompute the next fire time from the (possibly changed) cron/enabled so an
	// edit takes effect immediately and toggling off clears the next run.
	next, err := scheduleNextRun(in.Cron, in.Enabled, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.NextRunAt = next
	sc, err := s.store.UpdateSchedule(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.writeScheduleErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSchedule(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRunSchedule dispatches a schedule immediately, out of band, without
// touching its cron cadence (next_run_at is untouched). Handy for testing a
// schedule or forcing an off-cycle run.
func (s *Server) handleRunSchedule(w http.ResponseWriter, r *http.Request) {
	sc, err := s.store.GetSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	spec, link, err := s.resolvePolicySpec(r.Context(), sc.ScanPolicyID, sc.TargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	addAuditFields(r,
		slog.String("scan_policy_id", link.ScanPolicyID),
		slog.String("target_id", link.TargetID),
	)
	link.Source = "schedule"
	link.ScheduleID = sc.ID
	scanID, err := s.orch.Submit(r.Context(), spec, link)
	if err != nil {
		if errors.Is(err, ErrScanCapacity) {
			http.Error(w, "scan admission capacity exhausted; retry later", http.StatusTooManyRequests)
			return
		}
		s.serverError(w, "run schedule", err)
		return
	}
	addAuditFields(r, slog.String("scan_id", scanID))
	writeJSON(w, http.StatusAccepted, map[string]string{"scan_id": scanID})
}

// writeScheduleErr maps store sentinels for schedule writes. An unknown target
// or scan policy surfaces as ErrInvalidRef (a FK violation), reported as a 400
// distinct from a 404 on the schedule itself; everything else falls through.
func (s *Server) writeScheduleErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrInvalidRef) {
		http.Error(w, "unknown scan_policy_id or target_id", http.StatusBadRequest)
		return
	}
	s.writeStoreErr(w, err)
}
