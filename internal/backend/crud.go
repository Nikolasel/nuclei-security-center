package backend

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// --- targets ---

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.ListTargets(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if ts == nil {
		ts = []store.Target{}
	}
	writeJSON(w, http.StatusOK, ts)
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var in store.Target
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validateTarget(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.CreatedBy = identityFrom(r.Context()).Subject
	t, err := s.store.CreateTarget(r.Context(), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleGetTarget(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetTarget(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	var in store.Target
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validateTarget(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	t, err := s.store.UpdateTarget(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteTarget(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- template sets ---

func (s *Server) handleListTemplateSets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.ListTemplateSets(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if ts == nil {
		ts = []store.TemplateSet{}
	}
	writeJSON(w, http.StatusOK, ts)
}

func (s *Server) handleCreateTemplateSet(w http.ResponseWriter, r *http.Request) {
	var in store.TemplateSet
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validateTemplateSet(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.CreatedBy = identityFrom(r.Context()).Subject
	t, err := s.store.CreateTemplateSet(r.Context(), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleGetTemplateSet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetTemplateSet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleUpdateTemplateSet(w http.ResponseWriter, r *http.Request) {
	var in store.TemplateSet
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validateTemplateSet(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	t, err := s.store.UpdateTemplateSet(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleDeleteTemplateSet(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteTemplateSet(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- shared helpers ---

// decodeJSON reads a JSON body (capped) into v, writing a 400 on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, v); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// writeStoreErr maps store sentinels to HTTP status codes. Non-sentinel errors
// are treated as internal: the raw (often %w-wrapped pgx/pgconn) detail is logged
// server-side and only a generic body reaches the caller, so SQL fragments and
// constraint/column names never leak to an authenticated user (CWE-209).
func (s *Server) writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, store.ErrConflict):
		http.Error(w, "a resource with that name already exists", http.StatusConflict)
	case errors.Is(err, store.ErrNodeOverlap):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, store.ErrLastCatchAll):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		s.serverError(w, "store error", err)
	}
}

// serverError logs the internal error detail and returns a generic 500 body, so
// internal detail is never surfaced to the client. op is a short server-side
// label for the failing operation.
func (s *Server) serverError(w http.ResponseWriter, op string, err error) {
	s.log.Error(op, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}
