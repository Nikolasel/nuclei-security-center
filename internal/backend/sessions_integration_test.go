package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestAdminSessionRevocationInvalidatesCookie proves the remediation for #189:
// an admin's DELETE terminates the victim's live session so the next request
// with that cookie is 401 rather than retaining the stolen admin role.
func TestAdminSessionRevocationInvalidatesCookiePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	// Create a victim session (alice, admin) that would normally retain admin
	// for the whole SESSION_TTL.
	victimCookie := "victim-cookie-" + types.NewID()
	victim := store.Session{
		ID:        victimCookie,
		Identity:  store.Identity{Subject: "alice-" + types.NewID(), Email: "alice@example.com", Roles: []string{RoleAdmin}},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.CreateSession(ctx, victim); err != nil {
		t.Fatalf("CreateSession(victim): %v", err)
	}

	// Sanity: victim cookie is valid before revocation.
	auth := &Authenticator{
		store: st,
		log:   slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		cfg:   AuthConfig{CookieName: "nsc_session", SecureCookie: false, SessionTTL: DefaultSessionTTL},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req.AddCookie(&http.Cookie{Name: "nsc_session", Value: victimCookie})
	if id, err := auth.identityFromRequest(req); err != nil || id.Subject != victim.Identity.Subject {
		t.Fatalf("victim identity before revoke = %+v err %v", id, err)
	}

	// Admin lists sessions and revokes alice's sessions via bulk endpoint.
	srv := &Server{
		store: st,
		auth:  auth,
		log:   slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	// List — must contain alice.
	listReq := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	listReq = listReq.WithContext(withIdentity(listReq.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	rr := httptest.NewRecorder()
	// Bypass requireRole for unit: call handler directly with admin identity already in context.
	// The handler itself does not check role; the outer wrapper does. So we call it directly
	// and verify the store path separately. For the HTTP path we test via the full router.
	srv.handleListSessions(rr, listReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("list sessions status = %d, want 200", rr.Code)
	}
	var listed struct {
		Items      []store.SessionInfo `json:"items"`
		Total      int                 `json:"total"`
		Limit      int                 `json:"limit"`
		NextCursor string              `json:"next_cursor"`
		Offset     int                 `json:"offset"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&listed); err != nil {
		t.Fatalf("decode listed sessions: %v", err)
	}
	if len(listed.Items) == 0 {
		t.Fatal("listed sessions empty, want alice")
	}
	if listed.Total == 0 {
		t.Fatal("listed total == 0, want >0")
	}

	// Bulk revoke alice's subject.
	bulkReq := httptest.NewRequest(http.MethodDelete, "/api/sessions?subject="+victim.Identity.Subject, nil)
	bulkReq.Header.Set("Origin", "http://localhost:8080")
	bulkReq = bulkReq.WithContext(withIdentity(bulkReq.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	bulkRR := httptest.NewRecorder()
	srv.handleDeleteSessions(bulkRR, bulkReq)
	if bulkRR.Code != http.StatusOK {
		t.Fatalf("bulk revoke status = %d, want 200", bulkRR.Code)
	}
	var revoked struct {
		Revoked int64 `json:"revoked"`
	}
	if err := json.NewDecoder(bulkRR.Body).Decode(&revoked); err != nil {
		t.Fatalf("decode revoked: %v", err)
	}
	if revoked.Revoked == 0 {
		t.Fatalf("bulk revoked = %d, want >0", revoked.Revoked)
	}

	// Victim cookie must now be invalid — identityFromRequest yields zero and
	// requireAuth would return 401.
	req2 := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req2.AddCookie(&http.Cookie{Name: "nsc_session", Value: victimCookie})
	if id, err := auth.identityFromRequest(req2); err != nil {
		t.Fatalf("identityFromRequest after revoke err = %v", err)
	} else if id.Subject != "" {
		t.Fatalf("victim identity after revoke = %+v, want empty (revoked)", id)
	}

	// Also prove the single-id path: create bob, delete by hashed id.
	bobCookie := "bob-cookie-" + types.NewID()
	bob := store.Session{
		ID:        bobCookie,
		Identity:  store.Identity{Subject: "bob-" + types.NewID(), Roles: []string{RoleViewer}},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.CreateSession(ctx, bob); err != nil {
		t.Fatalf("CreateSession(bob): %v", err)
	}
	rows, _, _, err := st.ListSessions(ctx, 50, "", "")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	var bobHashed string
	for _, r := range rows {
		if r.Subject == bob.Identity.Subject {
			bobHashed = r.ID
			break
		}
	}
	if bobHashed == "" {
		t.Fatal("bob session not found in list")
	}
	delReq := httptest.NewRequest(http.MethodDelete, "/api/sessions/"+bobHashed, nil)
	delReq.Header.Set("Origin", "http://localhost:8080")
	delReq.SetPathValue("id", bobHashed)
	delReq = delReq.WithContext(withIdentity(delReq.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	delRR := httptest.NewRecorder()
	srv.handleDeleteSession(delRR, delReq)
	if delRR.Code != http.StatusNoContent {
		t.Fatalf("single revoke status = %d, want 204", delRR.Code)
	}
	if _, err := st.GetSession(ctx, bobCookie); err != store.ErrNotFound {
		t.Fatalf("GetSession(bob) after single revoke = %v, want ErrNotFound", err)
	}
}

// TestSessionsRouteRequiresAdmin verifies the router enforces admin on the new
// endpoints (#189) through the standard requireRole/mutation wrappers.
func TestSessionsRouteRequiresAdminPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	auth := &Authenticator{
		store: st,
		log:   slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		cfg:   AuthConfig{CookieName: "nsc_session", SecureCookie: false, SessionTTL: DefaultSessionTTL},
	}
	srv := NewServer(st, nil, auth, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")
	h := srv.Handler()

	// Create a viewer session.
	viewerCookie := "viewer-cookie-" + types.NewID()
	viewer := store.Session{
		ID:        viewerCookie,
		Identity:  store.Identity{Subject: "viewer-" + types.NewID(), Roles: []string{RoleViewer}},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.CreateSession(ctx, viewer); err != nil {
		t.Fatalf("CreateSession(viewer): %v", err)
	}

	// Viewer tries to list sessions — must be 403 (via mutation/requireRole).
	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.AddCookie(&http.Cookie{Name: "nsc_session", Value: viewerCookie})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer list sessions status = %d, want 403", rr.Code)
	}

	// Viewer tries to revoke by subject — 403.
	req2 := httptest.NewRequest(http.MethodDelete, "/api/sessions?subject=someone@example.com", nil)
	req2.AddCookie(&http.Cookie{Name: "nsc_session", Value: viewerCookie})
	req2.Header.Set("Origin", "http://localhost:8080")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("viewer bulk revoke status = %d, want 403", rr2.Code)
	}

	// Admin can list (200). Create admin session.
	adminCookie := "admin-cookie-" + types.NewID()
	admin := store.Session{
		ID:        adminCookie,
		Identity:  store.Identity{Subject: "admin-" + types.NewID(), Roles: []string{RoleAdmin}},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.CreateSession(ctx, admin); err != nil {
		t.Fatalf("CreateSession(admin): %v", err)
	}
	req3 := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req3.AddCookie(&http.Cookie{Name: "nsc_session", Value: adminCookie})
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("admin list sessions status = %d, want 200 body %s", rr3.Code, rr3.Body.String())
	}
	_ = types.NewID
}

// TestSessionsPaginationCursorAndSearch covers #252 cursor pagination, limit
// clamping, invalid cursor, and server-side q filtering through the handler.
func TestSessionsPaginationCursorAndSearchPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	auth := &Authenticator{
		store: st,
		log:   slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		cfg:   AuthConfig{CookieName: "nsc_session", SecureCookie: false, SessionTTL: DefaultSessionTTL},
	}
	srv := NewServer(st, nil, auth, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")

	// Create 3 distinct subjects.
	for _, sub := range []string{"alice-cursor", "bob-cursor", "alice2-cursor"} {
		if err := st.CreateSession(ctx, store.Session{ID: "cookie-" + sub + "-" + types.NewID(), Identity: store.Identity{Subject: sub, Email: sub + "@example.com", Roles: []string{"viewer"}}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatalf("CreateSession %s: %v", sub, err)
		}
	}

	adminCookie := "admin-cursor-" + types.NewID()
	adminSub := "admin-cursor-" + types.NewID()
	if err := st.CreateSession(ctx, store.Session{ID: adminCookie, Identity: store.Identity{Subject: adminSub, Roles: []string{RoleAdmin}}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("CreateSession admin: %v", err)
	}

	// Limit exceeds ceiling should clamp to default (50) and not error.
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=999", nil)
	req.AddCookie(&http.Cookie{Name: "nsc_session", Value: adminCookie})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("limit clamp status = %d, want 200", rr.Code)
	}
	var resp struct {
		Items []store.SessionInfo `json:"items"`
		Limit int                 `json:"limit"`
		Total int                 `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode clamp: %v", err)
	}
	if resp.Limit != store.DefaultSessionPageLimit {
		t.Fatalf("clamped limit = %d, want %d", resp.Limit, store.DefaultSessionPageLimit)
	}

	// Invalid cursor should be 400.
	req2 := httptest.NewRequest(http.MethodGet, "/api/sessions?cursor=bad", nil)
	req2.AddCookie(&http.Cookie{Name: "nsc_session", Value: adminCookie})
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("invalid cursor status = %d, want 400", rr2.Code)
	}

	// Server-side search: q=alice should return only alice subjects globally.
	req3 := httptest.NewRequest(http.MethodGet, "/api/sessions?q=alice-cursor&limit=10", nil)
	req3.AddCookie(&http.Cookie{Name: "nsc_session", Value: adminCookie})
	rr3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("search status = %d, want 200", rr3.Code)
	}
	var searched struct {
		Items []store.SessionInfo `json:"items"`
		Total int                 `json:"total"`
	}
	if err := json.NewDecoder(rr3.Body).Decode(&searched); err != nil {
		t.Fatalf("decode search: %v", err)
	}
	if searched.Total != 2 {
		t.Fatalf("search alice total = %d, want 2", searched.Total)
	}
	for _, it := range searched.Items {
		if it.Subject != "alice-cursor" && it.Subject != "alice2-cursor" {
			t.Fatalf("search alice item subject = %q, want alice", it.Subject)
		}
	}

	// Legacy offset shim still works for cached SPA.
	req4 := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=1&offset=0", nil)
	req4.AddCookie(&http.Cookie{Name: "nsc_session", Value: adminCookie})
	rr4 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusOK {
		t.Fatalf("offset shim status = %d, want 200", rr4.Code)
	}
	var offsetResp struct {
		Items  []store.SessionInfo `json:"items"`
		Offset int                 `json:"offset"`
		Total  int                 `json:"total"`
	}
	if err := json.NewDecoder(rr4.Body).Decode(&offsetResp); err != nil {
		t.Fatalf("decode offset: %v", err)
	}
	if offsetResp.Offset != 0 || len(offsetResp.Items) != 1 {
		t.Fatalf("offset shim = %+v, want offset 0 and 1 item", offsetResp)
	}
}
