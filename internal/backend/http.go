package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

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
	log   *slog.Logger
}

// NewServer builds the backend HTTP server. auth may be nil to disable auth.
func NewServer(st *store.Store, orch *Orchestrator, auth *Authenticator, log *slog.Logger) *Server {
	return &Server{store: st, orch: orch, auth: auth, log: log}
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

// Handler returns the backend router. Authorization per endpoint: reads need
// viewer, running scans and config writes need operator, deletes need admin.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Auth (public entry points; /auth/me needs a session).
	if s.auth != nil {
		mux.HandleFunc("GET /auth/login", s.auth.handleLogin)
		mux.HandleFunc("GET /auth/callback", s.auth.handleCallback)
		mux.HandleFunc("POST /auth/logout", s.auth.handleLogout)
	}
	mux.HandleFunc("GET /auth/me", s.requireAuth(s.handleMe))

	// Scans
	mux.HandleFunc("POST /scans", s.requireRole(RoleOperator, s.handleCreateScan))
	mux.HandleFunc("GET /scans/{id}", s.requireRole(RoleViewer, s.handleGetScan))
	mux.HandleFunc("GET /findings", s.requireRole(RoleViewer, s.handleListFindings))

	// Targets (config)
	mux.HandleFunc("GET /targets", s.requireRole(RoleViewer, s.handleListTargets))
	mux.HandleFunc("POST /targets", s.requireRole(RoleOperator, s.handleCreateTarget))
	mux.HandleFunc("GET /targets/{id}", s.requireRole(RoleViewer, s.handleGetTarget))
	mux.HandleFunc("PUT /targets/{id}", s.requireRole(RoleOperator, s.handleUpdateTarget))
	mux.HandleFunc("DELETE /targets/{id}", s.requireRole(RoleAdmin, s.handleDeleteTarget))

	// Template sets (config)
	mux.HandleFunc("GET /template-sets", s.requireRole(RoleViewer, s.handleListTemplateSets))
	mux.HandleFunc("POST /template-sets", s.requireRole(RoleOperator, s.handleCreateTemplateSet))
	mux.HandleFunc("GET /template-sets/{id}", s.requireRole(RoleViewer, s.handleGetTemplateSet))
	mux.HandleFunc("PUT /template-sets/{id}", s.requireRole(RoleOperator, s.handleUpdateTemplateSet))
	mux.HandleFunc("DELETE /template-sets/{id}", s.requireRole(RoleAdmin, s.handleDeleteTemplateSet))

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
		target, err := s.store.GetTarget(ctx, req.TargetID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("unknown target_id %q", req.TargetID)
			}
			return types.ScanSpec{}, store.ScanLink{}, err
		}
		spec := types.ScanSpec{Targets: target.Hosts, Options: defaultOptions()}
		link := store.ScanLink{TargetID: target.ID}
		if req.TemplateSetID != "" {
			ts, err := s.store.GetTemplateSet(ctx, req.TemplateSetID)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("unknown template_set_id %q", req.TemplateSetID)
				}
				return types.ScanSpec{}, store.ScanLink{}, err
			}
			spec.Templates = ts.Selector()
			link.TemplateSetID = ts.ID
		}
		return spec, link, nil

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

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("scan_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.store.ListFindings(r.Context(), scanID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []store.FindingRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
