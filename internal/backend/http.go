package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Server is the backend's HTTP API. Mutating and read endpoints are guarded by
// OIDC/BFF auth (§6); when auth is nil (OIDC unconfigured) the guards fall back
// to a dev identity with all roles, so local smoke tests still work.
type Server struct {
	store *store.Store
	orch  *Orchestrator
	auth  *Authenticator
	spa   http.Handler
	log   *slog.Logger
}

// NewServer builds the backend HTTP server. auth may be nil to disable auth; spa
// is the handler for the embedded frontend (served for all non-/api routes).
func NewServer(st *store.Store, orch *Orchestrator, auth *Authenticator, spa http.Handler, log *slog.Logger) *Server {
	return &Server{store: st, orch: orch, auth: auth, spa: spa, log: log}
}

// defaultOptions are the sane rate/concurrency/timeout defaults applied when a
// caller doesn't specify their own.
func defaultOptions() types.ScanOptions {
	return types.ScanOptions{RateLimit: 150, Concurrency: 25, TimeoutSec: 600}
}

// DefaultSpec is the fallback scan (ProjectDiscovery's public test host), used
// when POST /scans is called with an empty body — handy for smoke tests.
func DefaultSpec() types.ScanSpec {
	return types.ScanSpec{Targets: []string{"scanme.sh"}, Options: defaultOptions()}
}

// Handler returns the backend router. The JSON API lives under /api/*; the SPA
// (embedded static build) is served at / with client-route fallback. /healthz
// stays at the root for infra probes. Authorization per endpoint: reads need
// viewer, running scans and config writes need operator, deletes need admin.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Auth (public entry points; /api/auth/me needs a session).
	if s.auth != nil {
		mux.HandleFunc("GET /api/auth/login", s.auth.handleLogin)
		mux.HandleFunc("GET /api/auth/callback", s.auth.handleCallback)
		mux.HandleFunc("POST /api/auth/logout", s.auth.handleLogout)
	}
	mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))

	// Scans. Mutations go through s.mutation (authz + a structured audit event);
	// reads stay on requireRole. A scan submit is dispatch, not config.
	mux.HandleFunc("GET /api/scans", s.requireRole(RoleViewer, s.handleListScans))
	mux.HandleFunc("POST /api/scans", s.mutation(eventScanDispatched, "scan.create", "scan", RoleOperator, s.handleCreateScan))
	mux.HandleFunc("GET /api/scans/{id}", s.requireRole(RoleViewer, s.handleGetScan))
	mux.HandleFunc("GET /api/scans/{id}/findings", s.requireRole(RoleViewer, s.handleListScanFindings))

	// Findings — the deduplicated, triageable lifecycle entities (§3). Analyst
	// overlays (disposition, severity recast) are mutations → operator; reads → viewer.
	mux.HandleFunc("GET /api/findings", s.requireRole(RoleViewer, s.handleListFindings))
	mux.HandleFunc("GET /api/findings/export", s.requireRole(RoleViewer, s.handleExportFindings))
	mux.HandleFunc("GET /api/findings/{id}", s.requireRole(RoleViewer, s.handleGetFinding))
	mux.HandleFunc("PATCH /api/findings/{id}/disposition", s.mutation(eventFindingTriaged, "finding.disposition", "finding", RoleOperator, s.handleSetDisposition))
	mux.HandleFunc("PATCH /api/findings/{id}/severity", s.mutation(eventFindingTriaged, "finding.recast", "finding", RoleOperator, s.handleRecastSeverity))

	// Targets (config)
	mux.HandleFunc("GET /api/targets", s.requireRole(RoleViewer, s.handleListTargets))
	mux.HandleFunc("POST /api/targets", s.mutation(eventConfigChanged, "target.create", "target", RoleOperator, s.handleCreateTarget))
	mux.HandleFunc("GET /api/targets/{id}", s.requireRole(RoleViewer, s.handleGetTarget))
	mux.HandleFunc("PUT /api/targets/{id}", s.mutation(eventConfigChanged, "target.update", "target", RoleOperator, s.handleUpdateTarget))
	mux.HandleFunc("DELETE /api/targets/{id}", s.mutation(eventConfigChanged, "target.delete", "target", RoleAdmin, s.handleDeleteTarget))

	// Schedules (config) — cron-driven scans. Reads → viewer; create/edit/run →
	// operator; delete → admin (matches targets/template-sets). Run is a dispatch.
	mux.HandleFunc("GET /api/schedules", s.requireRole(RoleViewer, s.handleListSchedules))
	mux.HandleFunc("POST /api/schedules", s.mutation(eventConfigChanged, "schedule.create", "schedule", RoleOperator, s.handleCreateSchedule))
	mux.HandleFunc("GET /api/schedules/{id}", s.requireRole(RoleViewer, s.handleGetSchedule))
	mux.HandleFunc("PUT /api/schedules/{id}", s.mutation(eventConfigChanged, "schedule.update", "schedule", RoleOperator, s.handleUpdateSchedule))
	mux.HandleFunc("POST /api/schedules/{id}/run", s.mutation(eventScanDispatched, "schedule.run", "schedule", RoleOperator, s.handleRunSchedule))
	mux.HandleFunc("DELETE /api/schedules/{id}", s.mutation(eventConfigChanged, "schedule.delete", "schedule", RoleAdmin, s.handleDeleteSchedule))

	// Template sets (config)
	mux.HandleFunc("GET /api/template-sets", s.requireRole(RoleViewer, s.handleListTemplateSets))
	mux.HandleFunc("POST /api/template-sets", s.mutation(eventConfigChanged, "template_set.create", "template_set", RoleOperator, s.handleCreateTemplateSet))
	mux.HandleFunc("GET /api/template-sets/{id}", s.requireRole(RoleViewer, s.handleGetTemplateSet))
	mux.HandleFunc("PUT /api/template-sets/{id}", s.mutation(eventConfigChanged, "template_set.update", "template_set", RoleOperator, s.handleUpdateTemplateSet))
	mux.HandleFunc("DELETE /api/template-sets/{id}", s.mutation(eventConfigChanged, "template_set.delete", "template_set", RoleAdmin, s.handleDeleteTemplateSet))

	// Unknown /api/* paths get a JSON-ish 404 rather than the SPA's index.html.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	// Everything else: the embedded SPA (falls back to index.html for client routes).
	mux.Handle("/", s.spa)

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMe returns the authenticated caller's identity (for the SPA to render).
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, identityFrom(r.Context()))
}

// createScanRequest launches a scan one of three ways: from a stored target
// (+ optional template set), from an ad-hoc raw spec, or — with an empty body —
// the default smoke-test scan.
type createScanRequest struct {
	TargetID      string          `json:"target_id"`
	TemplateSetID string          `json:"template_set_id"`
	Spec          *types.ScanSpec `json:"spec"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	spec, link, err := s.buildScanSpec(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanID, err := s.orch.Submit(r.Context(), spec, link)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"scan_id": scanID})
}

// buildScanSpec resolves a createScanRequest into a concrete spec + config link.
func (s *Server) buildScanSpec(ctx context.Context, req createScanRequest) (types.ScanSpec, store.ScanLink, error) {
	if req.TemplateSetID != "" && req.TargetID == "" {
		return types.ScanSpec{}, store.ScanLink{}, errors.New("template_set_id requires a target_id")
	}

	switch {
	case req.TargetID != "":
		return s.resolveConfigSpec(ctx, req.TargetID, req.TemplateSetID)

	case req.Spec != nil:
		spec := *req.Spec
		if len(spec.Targets) == 0 {
			return types.ScanSpec{}, store.ScanLink{}, errors.New("spec.targets must not be empty")
		}
		if spec.Options == (types.ScanOptions{}) {
			spec.Options = defaultOptions()
		}
		return spec, store.ScanLink{}, nil

	default:
		return DefaultSpec(), store.ScanLink{}, nil
	}
}

// resolveConfigSpec builds a scan spec + config link from a stored target and an
// optional template set. Shared by ad-hoc "run from config" and the scheduler,
// so both dispatch identical scans from the same stored config.
func (s *Server) resolveConfigSpec(ctx context.Context, targetID, templateSetID string) (types.ScanSpec, store.ScanLink, error) {
	target, err := s.store.GetTarget(ctx, targetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("unknown target_id %q", targetID)
		}
		return types.ScanSpec{}, store.ScanLink{}, err
	}
	spec := types.ScanSpec{Targets: target.Hosts, Options: defaultOptions()}
	link := store.ScanLink{TargetID: target.ID}
	if templateSetID != "" {
		ts, err := s.store.GetTemplateSet(ctx, templateSetID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("unknown template_set_id %q", templateSetID)
			}
			return types.ScanSpec{}, store.ScanLink{}, err
		}
		spec.Templates = ts.Selector()
		link.TemplateSetID = ts.ID
	}
	return spec, link, nil
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.store.ListScans(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []store.ScanRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	row, err := s.store.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, row)
}

// pageParams parses the shared limit/offset pagination knobs.
func pageParams(q url.Values) (limit, offset int) {
	limit, _ = strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset, _ = strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// findingsPage is the paginated envelope returned by GET /api/findings (the
// deduplicated lifecycle view).
type findingsPage struct {
	Items  []store.LifecycleRow `json:"items"`
	Total  int                  `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

// lifecycleFilterFromQuery parses the shared findings filter query params (used
// by both the list and export endpoints). Limit/Offset are left zero.
func lifecycleFilterFromQuery(q url.Values) store.LifecycleFilter {
	return store.LifecycleFilter{
		TargetID:    q.Get("target_id"),
		Query:       strings.TrimSpace(q.Get("q")),
		Severities:  splitCSV(q.Get("severity")),
		Host:        strings.TrimSpace(q.Get("host")),
		CVE:         strings.TrimSpace(q.Get("cve")),
		Tag:         strings.TrimSpace(q.Get("tag")),
		Disposition: strings.TrimSpace(q.Get("disposition")),
		State:       strings.TrimSpace(q.Get("state")),
	}
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := pageParams(q)
	filter := lifecycleFilterFromQuery(q)
	filter.Limit = limit
	filter.Offset = offset
	rows, total, err := s.store.ListLifecycleFindings(r.Context(), filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []store.LifecycleRow{}
	}
	writeJSON(w, http.StatusOK, findingsPage{Items: rows, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid finding id", http.StatusBadRequest)
		return
	}
	d, err := s.store.GetLifecycleFinding(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// actorFrom returns a stable identifier for the authenticated caller (email,
// falling back to subject) to stamp on an audit field.
func actorFrom(r *http.Request) string {
	id := identityFrom(r.Context())
	if id.Email != "" {
		return id.Email
	}
	return id.Subject
}

// setDispositionRequest is the body of PATCH /api/findings/{id}/disposition.
// AcceptExpiresAt is honoured only for the "accepted" disposition (Accept Risk).
type setDispositionRequest struct {
	Disposition     string     `json:"disposition"`
	Note            string     `json:"note"`
	AcceptExpiresAt *time.Time `json:"accept_expires_at"`
}

func (s *Server) handleSetDisposition(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid finding id", http.StatusBadRequest)
		return
	}
	var req setDispositionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !store.ValidDisposition(req.Disposition) {
		http.Error(w, "invalid disposition (want one of: none, false_positive, accepted)", http.StatusBadRequest)
		return
	}
	if err := s.store.SetDisposition(r.Context(), id, req.Disposition, strings.TrimSpace(req.Note), actorFrom(r), req.AcceptExpiresAt); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.writeFinding(w, r, id)
}

// recastSeverityRequest is the body of PATCH /api/findings/{id}/severity. An empty
// severity clears the recast (reverting to the scan-observed severity).
type recastSeverityRequest struct {
	Severity string `json:"severity"`
	Note     string `json:"note"`
}

func (s *Server) handleRecastSeverity(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid finding id", http.StatusBadRequest)
		return
	}
	var req recastSeverityRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	sev := strings.TrimSpace(req.Severity)
	if sev != "" && !store.ValidSeverity(sev) {
		http.Error(w, "invalid severity (want one of: critical, high, medium, low, info — or empty to clear)", http.StatusBadRequest)
		return
	}
	if err := s.store.RecastSeverity(r.Context(), id, sev, strings.TrimSpace(req.Note), actorFrom(r)); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.writeFinding(w, r, id)
}

// writeFinding re-reads a lifecycle finding and writes it as the response (the
// updated entity returned by the disposition/recast mutations).
func (s *Server) writeFinding(w http.ResponseWriter, r *http.Request, id int64) {
	d, err := s.store.GetLifecycleFinding(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// handleListScanFindings returns the immutable per-scan occurrences observed by
// one scan (the scan-detail view), paginated + filterable like the main list.
func (s *Server) handleListScanFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := pageParams(q)
	filter := store.FindingFilter{
		ScanID:     r.PathValue("id"),
		Query:      strings.TrimSpace(q.Get("q")),
		Severities: splitCSV(q.Get("severity")),
		Host:       strings.TrimSpace(q.Get("host")),
		CVE:        strings.TrimSpace(q.Get("cve")),
		Tag:        strings.TrimSpace(q.Get("tag")),
		Limit:      limit,
		Offset:     offset,
	}
	rows, total, err := s.store.ListFindings(r.Context(), filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []store.FindingRow{}
	}
	writeJSON(w, http.StatusOK, occurrencesPage{Items: rows, Total: total, Limit: limit, Offset: offset})
}

// occurrencesPage is the paginated envelope for per-scan occurrences.
type occurrencesPage struct {
	Items  []store.FindingRow `json:"items"`
	Total  int                `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}

// splitCSV splits a comma-separated query value, trimming spaces and dropping empties.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
