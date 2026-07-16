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
	store    *store.Store
	orch     *Orchestrator
	auth     *Authenticator
	archive  ObjectStore      // nil when object storage is not configured
	searcher FindingsSearcher // reads the findings list; defaults to Postgres
	spa      http.Handler
	log      *slog.Logger
}

// NewServer builds the backend HTTP server. auth may be nil to disable auth; spa
// is the handler for the embedded frontend (served for all non-/api routes). The
// findings searcher defaults to Postgres; SetFindingsSearcher swaps it.
func NewServer(st *store.Store, orch *Orchestrator, auth *Authenticator, archive ObjectStore, spa http.Handler, log *slog.Logger) *Server {
	return &Server{store: st, orch: orch, auth: auth, archive: archive, searcher: pgSearcher{store: st}, spa: spa, log: log}
}

// SetFindingsSearcher swaps the backend for GET /api/findings (default: Postgres).
func (s *Server) SetFindingsSearcher(searcher FindingsSearcher) { s.searcher = searcher }

// defaultOptions are the sane rate/concurrency/timeout defaults applied when a
// caller doesn't specify their own.
func defaultOptions() types.ScanOptions {
	return types.ScanOptions{RateLimit: 150, Concurrency: 25, TimeoutSec: 600}
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
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.mutation(eventScanDispatched, "scan.cancel", "scan", RoleOperator, s.handleCancelScan))
	mux.HandleFunc("DELETE /api/scans/{id}", s.mutation(eventScanDispatched, "scan.delete", "scan", RoleAdmin, s.handleDeleteScan))
	mux.HandleFunc("GET /api/scans/{id}/findings", s.requireRole(RoleViewer, s.handleListScanFindings))
	mux.HandleFunc("GET /api/scans/{id}/raw", s.requireRole(RoleViewer, s.handleGetScanRaw))

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

	// Service accounts (#70) — NSC-local API-token identities for headless
	// automation. Managing these credentials is admin-only; create/rotate/revoke
	// are audited under a dedicated security event id. The token itself is only
	// ever returned in the create/rotate response body, never on list.
	mux.HandleFunc("GET /api/service-accounts", s.requireRole(RoleAdmin, s.handleListServiceAccounts))
	mux.HandleFunc("POST /api/service-accounts", s.mutation(eventServiceAccountChanged, "service_account.create", "service_account", RoleAdmin, s.handleCreateServiceAccount))
	mux.HandleFunc("POST /api/service-accounts/{id}/rotate", s.mutation(eventServiceAccountChanged, "service_account.rotate", "service_account", RoleAdmin, s.handleRotateServiceAccount))
	mux.HandleFunc("DELETE /api/service-accounts/{id}", s.mutation(eventServiceAccountChanged, "service_account.revoke", "service_account", RoleAdmin, s.handleDeleteServiceAccount))

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
// the default smoke-test scan. TimeoutSec overrides defaultOptions' fixed
// 600s for the stored-target path (the ad-hoc spec path already carries its
// own Options.TimeoutSec) — a target scoped to a large CIDR range needs more
// than 10 minutes, and there was previously no way to ask for it.
type createScanRequest struct {
	TargetID      string          `json:"target_id"`
	TemplateSetID string          `json:"template_set_id"`
	Spec          *types.ScanSpec `json:"spec"`
	TimeoutSec    *int            `json:"timeout_sec,omitempty"`
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
		s.serverError(w, "submit scan", err)
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
		spec, link, err := s.resolveConfigSpec(ctx, req.TargetID, req.TemplateSetID)
		if err != nil {
			return spec, link, err
		}
		if req.TimeoutSec != nil {
			if *req.TimeoutSec <= 0 {
				return types.ScanSpec{}, store.ScanLink{}, errors.New("timeout_sec must be positive")
			}
			spec.Options.TimeoutSec = *req.TimeoutSec
		}
		return spec, link, nil

	case req.Spec != nil:
		spec := *req.Spec
		if len(spec.Targets) == 0 {
			return types.ScanSpec{}, store.ScanLink{}, errors.New("spec.targets must not be empty")
		}
		// An ad-hoc spec bypasses the stored-target allowlist, so validate the
		// host formats and enforce the scope guardrail (§6) here: every target
		// must fall inside an approved target record.
		for i, h := range spec.Targets {
			h = strings.TrimSpace(h)
			if err := validateHost(h); err != nil {
				return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("target %q: %w", h, err)
			}
			spec.Targets[i] = h
		}
		if err := s.enforceScope(ctx, spec.Targets); err != nil {
			return types.ScanSpec{}, store.ScanLink{}, err
		}
		// The scope guardrail covers hosts, not template sources. Validate the
		// template selectors with the same rules as stored template sets so an
		// ad-hoc spec can't steer `nuclei -templates` to an arbitrary path/ref.
		spec.Templates.GitRef = strings.TrimSpace(spec.Templates.GitRef)
		spec.Templates.Paths = trimAll(spec.Templates.Paths)
		if err := validateTemplateSelector(spec.Templates.Paths, spec.Templates.GitRef); err != nil {
			return types.ScanSpec{}, store.ScanLink{}, err
		}
		if spec.Options == (types.ScanOptions{}) {
			spec.Options = defaultOptions()
		}
		return spec, store.ScanLink{}, nil

	default:
		return types.ScanSpec{}, store.ScanLink{}, errors.New("provide target_id (a stored target) or spec.targets")
	}
}

// enforceScope rejects a scan whose targets aren't all covered by an approved
// target record — the scope guardrail (§6). It fails closed: with no approved
// targets, every host is out of scope.
func (s *Server) enforceScope(ctx context.Context, targets []string) error {
	approved, err := s.store.AllTargetHosts(ctx)
	if err != nil {
		return fmt.Errorf("load approved scope: %w", err)
	}
	if bad := outOfScopeHosts(approved, targets); len(bad) > 0 {
		return fmt.Errorf("out of scope (not inside any approved target): %s", strings.Join(bad, ", "))
	}
	return nil
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
		s.serverError(w, "list scans", err)
		return
	}
	if rows == nil {
		rows = []store.ScanRow{}
	}
	// Attach live progress (#66) to running scans from the orchestrator's cache.
	for i := range rows {
		if rows[i].State == string(types.ScanRunning) {
			rows[i].Progress = s.orch.Progress(rows[i].ID)
		}
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
		s.serverError(w, "get scan", err)
		return
	}
	if row.State == string(types.ScanRunning) {
		row.Progress = s.orch.Progress(row.ID)
	}
	writeJSON(w, http.StatusOK, row)
}

// handleCancelScan stops a queued/running scan (operator). It flips the scan to
// cancelled (the DB update is the authority on the transition), then best-effort
// signals the node to abort the in-progress run. A scan that isn't in a
// cancellable state gets 409; an unknown scan gets 404.
func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := identityFrom(r.Context())
	reason := "cancelled by " + firstNonEmpty(actor.Name, actor.Email, actor.Subject, "operator")
	nodeScanID, cancelled, err := s.store.CancelScan(r.Context(), id, reason)
	if err != nil {
		s.serverError(w, "cancel scan", err)
		return
	}
	if !cancelled {
		// Not cancellable: distinguish gone (404) from already-terminal (409).
		if _, gerr := s.store.GetScan(r.Context(), id); errors.Is(gerr, store.ErrNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		http.Error(w, "scan is not in a cancellable state", http.StatusConflict)
		return
	}
	// Detached from the request so a client disconnect can't leave the node
	// running; the DB already reflects cancelled either way.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		s.orch.SignalNodeCancel(ctx, nodeScanID)
	}()
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteScan removes a scan record (admin). Its findings occurrences
// cascade; lifecycle references are set NULL by the schema. A queued/running
// scan can't be deleted (409) — cancel it first. The archived raw object is
// purged best-effort (storage cleanup must never fail the delete, since Postgres
// is already the system of record and the row is gone).
func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rawKey, err := s.store.DeleteScan(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			http.Error(w, "scan not found", http.StatusNotFound)
		case errors.Is(err, store.ErrConflict):
			http.Error(w, "cancel the scan before deleting it", http.StatusConflict)
		default:
			s.serverError(w, "delete scan", err)
		}
		return
	}
	if s.archive != nil && rawKey != "" {
		if err := s.archive.Delete(r.Context(), rawKey); err != nil {
			s.log.Warn("purge archived raw output", "scan_id", id, "key", rawKey, "err", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetScanRaw streams a scan's archived verbatim Nuclei output (out.jsonl)
// from object storage, through the BFF so it stays behind the session cookie
// (same trust model as the exports — no presigned URLs leaking the bucket).
func (s *Server) handleGetScanRaw(w http.ResponseWriter, r *http.Request) {
	if s.archive == nil {
		http.Error(w, "object storage is not configured", http.StatusNotFound)
		return
	}
	id := r.PathValue("id")
	key, err := s.store.ScanRawKey(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		s.serverError(w, "get scan raw key", err)
		return
	}
	if key == "" {
		http.Error(w, "no archived output for this scan", http.StatusNotFound)
		return
	}

	obj, err := s.archive.Get(r.Context(), key)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			http.Error(w, "archived output is missing from storage", http.StatusNotFound)
			return
		}
		s.serverError(w, "get archived raw output", err)
		return
	}
	defer obj.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%s.jsonl"`, id))
	if _, err := io.Copy(w, obj); err != nil {
		s.log.Warn("stream raw archive", "scan_id", id, "err", err)
	}
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
	rows, total, err := s.searcher.ListLifecycle(r.Context(), filter)
	if err != nil {
		s.serverError(w, "list lifecycle findings", err)
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
		s.writeStoreErr(w, err)
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
		s.writeStoreErr(w, err)
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
		s.writeStoreErr(w, err)
		return
	}
	s.writeFinding(w, r, id)
}

// writeFinding re-reads a lifecycle finding and writes it as the response (the
// updated entity returned by the disposition/recast mutations).
func (s *Server) writeFinding(w http.ResponseWriter, r *http.Request, id int64) {
	d, err := s.store.GetLifecycleFinding(r.Context(), id)
	if err != nil {
		s.writeStoreErr(w, err)
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
		s.serverError(w, "list scan findings", err)
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
