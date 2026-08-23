package backend

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// handleListSessions returns live sessions for admin inspection (#189, #252).
// Admin only; audited via the mutation wrapper is not needed for a read, but
// the list itself is sensitive — keep it admin-gated.
//
// Pagination (#252): the endpoint is server-enforced keyset-paginated (limit +
// cursor over (created_at DESC, id DESC)) with a hard ceiling of
// MaxSessionPageLimit, so concurrent revocations/expirations cannot cause skipped
// rows. A `q` param filters server-side across subject/email/name/roles.
// The response is `{items, total, limit, next_cursor}` where next_cursor is an
// opaque token for the next page (empty at EOF) and total is the filtered live
// count. Legacy `offset` pagination is still accepted as a compatibility shim
// for a cached SPA that has not yet reloaded the new bundle; it uses a stable
// ordering (created_at DESC, id DESC) and returns the historic `{items, total,
// limit, offset}` envelope plus next_cursor so the caller can migrate. New
// clients must use `cursor`; `offset` is deprecated and will be removed.
// This is a breaking change from the pre-#252 bare-array response and the
// offset-only envelope: API clients must read `.items` and iterate via
// `next_cursor` (or `offset` shim) rather than expecting the full set.
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cursor := strings.TrimSpace(q.Get("cursor"))
	search := strings.TrimSpace(q.Get("q"))
	if len(search) > 256 {
		http.Error(w, "q exceeds 256-byte limit", http.StatusBadRequest)
		return
	}
	// Cursor pagination (including server-side search). `cursor` is an opaque
	// token for the next page; `q` filters globally across subject/email/name/roles.
	if cursor != "" || search != "" {
		limit := parseSessionLimit(q.Get("limit"))
		rows, nextCursor, total, err := s.store.ListSessions(r.Context(), limit, cursor, search)
		if err != nil {
			if strings.Contains(err.Error(), "invalid cursor") {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.serverError(w, "list sessions", err)
			return
		}
		if rows == nil {
			rows = []store.SessionInfo{}
		}
		writeJSON(w, http.StatusOK, sessionsPage{Items: rows, Total: total, Limit: limit, NextCursor: nextCursor})
		return
	}
	// Legacy offset shim for a cached SPA that still sends `?limit=&offset=`.
	if q.Has("offset") {
		limit, offset := pageParams(q)
		if limit > store.MaxSessionPageLimit {
			limit = store.MaxSessionPageLimit
		}
		rows, total, err := s.store.ListSessionsOffset(r.Context(), limit, offset, search)
		if err != nil {
			s.serverError(w, "list sessions", err)
			return
		}
		if rows == nil {
			rows = []store.SessionInfo{}
		}
		var nextCursor string
		if len(rows) > 0 && offset+limit < total {
			last := rows[len(rows)-1]
			nextCursor = encodeSessionCursorForHandler(last.CreatedAt, last.ID)
		}
		writeJSON(w, http.StatusOK, sessionsPage{Items: rows, Total: total, Limit: limit, Offset: offset, NextCursor: nextCursor})
		return
	}
	// Default first page via cursor.
	limit := parseSessionLimit(q.Get("limit"))
	rows, nextCursor, total, err := s.store.ListSessions(r.Context(), limit, "", search)
	if err != nil {
		s.serverError(w, "list sessions", err)
		return
	}
	if rows == nil {
		rows = []store.SessionInfo{}
	}
	writeJSON(w, http.StatusOK, sessionsPage{Items: rows, Total: total, Limit: limit, NextCursor: nextCursor})
}

func parseSessionLimit(raw string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(raw))
	if n <= 0 || n > store.MaxSessionPageLimit {
		return store.DefaultSessionPageLimit
	}
	return n
}

// encodeSessionCursorForHandler mirrors store.encodeSessionCursor for the legacy offset shim.
func encodeSessionCursorForHandler(t time.Time, id string) string {
	b, _ := json.Marshal(struct {
		CreatedAt time.Time `json:"created_at"`
		ID        string    `json:"id"`
	}{CreatedAt: t.UTC(), ID: id})
	return base64.RawURLEncoding.EncodeToString(b)
}

// sessionsPage is the paginated envelope for GET /api/sessions (#252).
type sessionsPage struct {
	Items      []store.SessionInfo `json:"items"`
	Total      int                 `json:"total"`
	Limit      int                 `json:"limit"`
	Offset     int                 `json:"offset,omitempty"`
	NextCursor string              `json:"next_cursor,omitempty"`
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
