package backend

import (
	"errors"
	"net/http"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func (s *Server) handleListTemplateSetExclusions(w http.ResponseWriter, r *http.Request) {
	exclusions, err := s.store.ListTemplateSetExclusions(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeExclusionErr(w, err)
		return
	}
	if exclusions == nil {
		exclusions = []store.Template{}
	}
	writeJSON(w, http.StatusOK, exclusions)
}

// handleReplaceTemplateSetExclusions replaces the exclusion list for an exclude
// set and returns the fresh set, including its effective member/exclusion counts.
func (s *Server) handleReplaceTemplateSetExclusions(w http.ResponseWriter, r *http.Request) {
	var in memberIDs
	if !decodeJSON(w, r, &in) {
		return
	}
	if _, err := s.store.ReplaceTemplateSetExclusions(
		r.Context(), r.PathValue("id"), in.TemplateIDs, identityFrom(r.Context()).Subject,
	); err != nil {
		s.writeExclusionErr(w, err)
		return
	}
	set, err := s.store.GetTemplateSet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) writeExclusionErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrInvalidRef) {
		http.Error(w, "one or more template_ids do not exist", http.StatusBadRequest)
		return
	}
	if errors.Is(err, store.ErrTemplateSetExclusionsUnsupported) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.writeStoreErr(w, err)
}
