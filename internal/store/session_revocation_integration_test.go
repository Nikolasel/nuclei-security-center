package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestListAndRevokeSessions pins the admin revocation path (#189): an admin can
// enumerate live sessions and terminate a user's sessions so a demoted/offboarded
// user loses access without waiting for SESSION_TTL expiry.
func TestListAndRevokeSessionsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	alice := "alice-" + types.NewID()
	bob := "bob-" + types.NewID()

	// Create three sessions: two for alice, one for bob.
	sessions := []Session{
		{ID: "alice-cookie-1-" + types.NewID(), Identity: Identity{Subject: alice, Email: "alice@example.com", Roles: []string{"admin"}}, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "alice-cookie-2-" + types.NewID(), Identity: Identity{Subject: alice, Email: "alice@example.com", Roles: []string{"admin"}}, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "bob-cookie-" + types.NewID(), Identity: Identity{Subject: bob, Email: "bob@example.com", Roles: []string{"viewer"}}, ExpiresAt: time.Now().Add(time.Hour)},
	}
	for _, sess := range sessions {
		if err := st.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	rows, err := st.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("ListSessions = %d, want 3", len(rows))
	}
	// Each row's ID must be the stored hash, not the raw cookie.
	for _, r := range rows {
		if r.ID == sessions[0].ID || r.ID == sessions[1].ID || r.ID == sessions[2].ID {
			t.Fatalf("ListSessions ID %q is raw cookie value; want hash", r.ID)
		}
		if r.Subject != alice && r.Subject != bob {
			t.Fatalf("ListSessions subject = %q, want alice or bob", r.Subject)
		}
	}

	// Revoke all of alice's sessions (offboarding).
	n, err := st.DeleteSessionsBySubject(ctx, alice)
	if err != nil {
		t.Fatalf("DeleteSessionsBySubject: %v", err)
	}
	if n != 2 {
		t.Fatalf("DeleteSessionsBySubject deleted %d, want 2", n)
	}
	// Alice's cookies must now be invalid (GetSession -> ErrNotFound).
	for _, sess := range sessions[:2] {
		if _, err := st.GetSession(ctx, sess.ID); err != ErrNotFound {
			t.Fatalf("GetSession(%q) after revoke = %v, want ErrNotFound", sess.ID, err)
		}
	}
	// Bob's session must still be valid.
	if _, err := st.GetSession(ctx, sessions[2].ID); err != nil {
		t.Fatalf("GetSession(bob) after alice revoke = %v, want nil", err)
	}

	// Revoke bob's single session by its hashed ID (list -> delete).
	rows, err = st.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions after alice revoke: %v", err)
	}
	if len(rows) != 1 || rows[0].Subject != bob {
		t.Fatalf("ListSessions after alice revoke = %+v, want 1 bob row", rows)
	}
	hashedID := rows[0].ID
	if err := st.DeleteSessionByID(ctx, hashedID); err != nil {
		t.Fatalf("DeleteSessionByID: %v", err)
	}
	if _, err := st.GetSession(ctx, sessions[2].ID); err != ErrNotFound {
		t.Fatalf("GetSession(bob) after DeleteSessionByID = %v, want ErrNotFound", err)
	}

	// All revoked — list must be empty.
	rows, err = st.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions final: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("ListSessions final = %d, want 0", len(rows))
	}
}

// TestListSessionsExcludesExpired verifies the sweeper's view: expired rows are
// not returned and are not revivable — they are already invalid.
func TestListSessionsExcludesExpiredPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	expired := Session{ID: "expired-" + types.NewID(), Identity: Identity{Subject: "carol"}, ExpiresAt: time.Now().Add(-time.Minute)}
	live := Session{ID: "live-" + types.NewID(), Identity: Identity{Subject: "carol"}, ExpiresAt: time.Now().Add(time.Hour)}
	if err := st.CreateSession(ctx, expired); err != nil {
		t.Fatalf("CreateSession(expired): %v", err)
	}
	if err := st.CreateSession(ctx, live); err != nil {
		t.Fatalf("CreateSession(live): %v", err)
	}
	rows, err := st.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(rows) != 1 || rows[0].Subject != "carol" {
		t.Fatalf("ListSessions with one expired = %+v, want 1 live", rows)
	}
	// Expired cookie is already ErrNotFound.
	if _, err := st.GetSession(ctx, expired.ID); err != ErrNotFound {
		t.Fatalf("GetSession(expired) = %v, want ErrNotFound", err)
	}
}
