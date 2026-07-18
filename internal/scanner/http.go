package scanner

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Server wires the Runner to the scanner node's HTTP API.
type Server struct {
	runner *Runner
	token  string
	log    *slog.Logger
}

// NewServer builds the scanner HTTP server. token is the shared bearer secret
// the backend must present.
func NewServer(runner *Runner, token string, log *slog.Logger) *Server {
	return &Server{runner: runner, token: token, log: log}
}

// Handler returns the router with auth applied to the /v1 API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Health is unauthenticated so orchestrators can probe it.
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /v1/scans", s.auth(s.handleStart))
	mux.HandleFunc("GET /v1/scans/{id}", s.auth(s.handleStatus))
	mux.HandleFunc("GET /v1/scans/{id}/results", s.auth(s.handleResults))
	mux.HandleFunc("POST /v1/scans/{id}/cancel", s.auth(s.handleCancel))
	mux.HandleFunc("GET /v1/capabilities", s.auth(s.handleCapabilities))
	return mux
}

// handleCapabilities reports the node's runtime facts (nuclei version, template
// commit). The backend polls this to derive node liveness (#98) — it is the read
// side of a strictly backend→node call, so it stays authed like the rest of /v1.
func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.runner.Capabilities())
}

// auth enforces the bearer token in constant time.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if len(h) <= len(prefix) || subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	var spec types.ScanSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		http.Error(w, "invalid scan spec: "+err.Error(), http.StatusBadRequest)
		return
	}
	id, err := s.runner.Start(spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.log.Info("scan started", "scan_id", id, "targets", len(spec.Targets))
	writeJSON(w, http.StatusAccepted, types.StartScanResponse{ScanID: id})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st, ok := s.runner.Status(r.PathValue("id"))
	if !ok {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	path, ok := s.runner.ResultsPath(r.PathValue("id"))
	if !ok {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		// No results file yet (or none produced) => empty stream, not an error.
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if !s.runner.Cancel(r.PathValue("id")) {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
