package backend

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// targetGroupRequest is the create/update body: a name plus the member target
// ids. Membership is a static set of existing targets (#13).
type targetGroupRequest struct {
	Name      string   `json:"name"`
	TargetIDs []string `json:"target_ids"`
}

func (r *targetGroupRequest) normalize() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return errors.New("name is required")
	}
	// De-dupe and drop blanks so the membership set is clean before it hits the DB.
	seen := map[string]bool{}
	out := make([]string, 0, len(r.TargetIDs))
	for _, id := range r.TargetIDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	r.TargetIDs = out
	return nil
}

func (s *Server) handleListTargetGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := s.store.ListTargetGroups(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if gs == nil {
		gs = []store.TargetGroup{}
	}
	writeJSON(w, http.StatusOK, gs)
}

func (s *Server) handleCreateTargetGroup(w http.ResponseWriter, r *http.Request) {
	var req targetGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.normalize(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g, err := s.store.CreateTargetGroup(r.Context(), req.Name, identityFrom(r.Context()).Subject, req.TargetIDs)
	if err != nil {
		s.writeTargetGroupErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) handleGetTargetGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetTargetGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleUpdateTargetGroup(w http.ResponseWriter, r *http.Request) {
	var req targetGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.normalize(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g, err := s.store.UpdateTargetGroup(r.Context(), r.PathValue("id"), req.Name, req.TargetIDs)
	if err != nil {
		s.writeTargetGroupErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleDeleteTargetGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteTargetGroup(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeTargetGroupErr maps an unknown member target (FK → ErrInvalidRef) to a
// 400, distinct from a 404 on the group itself.
func (s *Server) writeTargetGroupErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrInvalidRef) {
		http.Error(w, "one or more target_ids do not exist", http.StatusBadRequest)
		return
	}
	s.writeStoreErr(w, err)
}
