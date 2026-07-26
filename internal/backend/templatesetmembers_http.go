package backend

import (
	"errors"
	"net/http"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// memberIDs is the request body for setting/adding template-set members: a plain
// list of catalog template ids (Nuclei ids, e.g. "CVE-2021-44228").
type memberIDs struct {
	TemplateIDs []string `json:"template_ids"`
}

func (s *Server) handleListTemplateSetMembers(w http.ResponseWriter, r *http.Request) {
	members, err := s.store.ListTemplateSetMembers(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if members == nil {
		members = []store.Template{}
	}
	writeJSON(w, http.StatusOK, members)
}

// handleReplaceTemplateSetMembers sets a set's membership to exactly the posted
// ids (the editor's save). Returns the fresh set (with the updated member_count).
func (s *Server) handleReplaceTemplateSetMembers(w http.ResponseWriter, r *http.Request) {
	var in memberIDs
	if !decodeJSON(w, r, &in) {
		return
	}
	if _, err := s.store.ReplaceTemplateSetMembers(r.Context(), r.PathValue("id"), in.TemplateIDs, identityFrom(r.Context()).Subject); err != nil {
		s.writeMemberErr(w, err)
		return
	}
	set, err := s.store.GetTemplateSet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

// handleAddTemplateSetMembers adds ids to a set (idempotent), returning the set.
func (s *Server) handleAddTemplateSetMembers(w http.ResponseWriter, r *http.Request) {
	var in memberIDs
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.store.AddTemplateSetMembers(r.Context(), r.PathValue("id"), in.TemplateIDs, identityFrom(r.Context()).Subject); err != nil {
		s.writeMemberErr(w, err)
		return
	}
	set, err := s.store.GetTemplateSet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleRemoveTemplateSetMember(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RemoveTemplateSetMember(r.Context(), r.PathValue("id"), r.PathValue("templateId")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeMemberErr maps a bad template id (FK violation, ErrInvalidRef) to a 400
// distinct from a 404 on the set itself; everything else falls through.
func (s *Server) writeMemberErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrInvalidRef) {
		http.Error(w, "one or more template_ids do not exist", http.StatusBadRequest)
		return
	}
	if errors.Is(err, store.ErrTemplateSetDynamic) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.writeStoreErr(w, err)
}
