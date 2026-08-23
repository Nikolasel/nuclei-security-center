package backend

import (
	"log/slog"
	"net/http"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// handleListSessions returns live sessions for admin inspection (#189, #252).
// Admin only; audited via the mutation wrapper is not needed for a read, but
// the list itself is sensitive — keep it admin-gated.
//
// Pagination (#252): the endpoint is server-enforced paginated (limit/offset
// with a hard ceiling of MaxSessionPageLimit) to prevent materializing an
// unbounded session table into memory and the response. The envelope mirrors
// GET /api/findings: {items, total, limit, offset}. Clients that omit
// pagination params get the default page (limit=50, offset=0).
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageParams(r.URL.Query())
	// Re-clamp to the tighter sessions ceiling (pageParams allows up to 500).
	if limit > store.MaxSessionPageLimit {
		limit = store.MaxSessionPageLimit
	}
	rows, total, err := s.store.ListSessions(r.Context(), limit, offset)
	if err != nil {
		s.serverError(w, "list sessions", err)
		return
	}
	if rows == nil {
		rows = []store.SessionInfo{}
	}
	writeJSON(w, http.StatusOK, sessionsPage{Items: rows, Total: total, Limit: limit, Offset: offset})
}

// sessionsPage is the paginated envelope for GET /api/sessions (#252).
type sessionsPage struct {
	Items  []store.SessionInfo `json:"items"`
	Total  int                 `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
}

// handleDeleteSession revokes a single session by its stored hashed ID (#189).
// Admin only, audited. The ID is the sessions PK (hash), not the raw cookie.
func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteSessionByID(r.Context(), id); err != nil {
		s.serverError(w, "revoke session", err)
		return
	}
	addAuditFields(r, slog.String("revoked_session_id", id))
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteSessions handles bulk revocation for a subject (#189).
// DELETE /api/sessions?subject=<subject> — admin only, audited. Removes every
// live session for that subject so an offboarded or demoted user loses access
// immediately without waiting for SESSION_TTL expiry. Subject is the OIDC `sub`
// claim (opaque, often a UUID), not the email — clients should copy it from
// GET /api/sessions; a 404 makes a typo or email-instead-of-sub obvious
// rather than silently returning {"revoked":0}. A correctly supplied `sub`
// with no live sessions also 404s (already-clean): offboarding automation
// should treat 404 as success. The audit record is emitted even for 404
// (revoked_count=0, status=404) so SIEM rules should key on revoked_count/
// status, not just event_id.
func (s *Server) handleDeleteSessions(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	if subject == "" {
		http.Error(w, "subject is required", http.StatusBadRequest)
		return
	}
	n, err := s.store.DeleteSessionsBySubject(r.Context(), subject)
	if err != nil {
		s.serverError(w, "revoke sessions", err)
		return
	}
	// Audited even when n==0 (404) so the attempt is in the trail; see
	// comment above for SIEM guidance.
	addAuditFields(r,
		slog.String("revoked_subject", subject),
		slog.Int64("revoked_count", n),
	)
	if n == 0 {
		http.Error(w, "no active sessions for subject", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}
