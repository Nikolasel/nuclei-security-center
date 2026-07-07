package backend

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Server is the backend's HTTP API. Phase 0 has no auth yet (OIDC/BFF lands in
// Phase 1); it exposes just enough to trigger a scan and read results.
type Server struct {
	store *store.Store
	orch  *Orchestrator
	log   *slog.Logger
}

// NewServer builds the backend HTTP server.
func NewServer(st *store.Store, orch *Orchestrator, log *slog.Logger) *Server {
	return &Server{store: st, orch: orch, log: log}
}

// DefaultSpec is the Phase 0 hardcoded scan: ProjectDiscovery's public test host.
// Used when POST /scans is called with an empty body.
func DefaultSpec() types.ScanSpec {
	return types.ScanSpec{
		Targets: []string{"scanme.sh"},
		Options: types.ScanOptions{RateLimit: 150, Concurrency: 25, TimeoutSec: 600},
	}
}

// Handler returns the backend router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /scans", s.handleCreateScan)
	mux.HandleFunc("GET /scans/{id}", s.handleGetScan)
	mux.HandleFunc("GET /findings", s.handleListFindings)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	spec := DefaultSpec()
	// Allow an optional spec override; empty body keeps the default.
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(body) > 0 {
		if err := json.Unmarshal(body, &spec); err != nil {
			http.Error(w, "invalid scan spec: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	scanID, err := s.orch.Submit(r.Context(), spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"scan_id": scanID})
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
