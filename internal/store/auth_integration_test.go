package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestGetSessionMissingAndExpiredReturnErrNotFound pins the contract consumed by
// backend authentication: a missing or expired cookie is a credential failure,
// not a store outage.
func TestGetSessionMissingAndExpiredReturnErrNotFound(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	t.Run("missing", func(t *testing.T) {
		_, err := st.GetSession(ctx, "missing-"+types.NewID())
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetSession(missing) error = %v, want ErrNotFound", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		id := "expired-" + types.NewID()
		if err := st.CreateSession(ctx, Session{
			ID:        id,
			Identity:  Identity{Subject: "expired-user"},
			ExpiresAt: time.Now().Add(-time.Minute),
		}); err != nil {
			t.Fatalf("CreateSession(expired): %v", err)
		}

		_, err := st.GetSession(ctx, id)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetSession(expired) error = %v, want ErrNotFound", err)
		}
	})
}

func TestSessionCookieValueIsHashedAtRestPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	const cookieValue = "session-cookie-value"
	const subject = "hashed-session-user"
	if err := st.CreateSession(ctx, Session{
		ID:        cookieValue,
		Identity:  Identity{Subject: subject},
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	var storedID string
	if err := st.pool.QueryRow(ctx, `SELECT id FROM sessions WHERE subject = $1`, subject).Scan(&storedID); err != nil {
		t.Fatalf("read stored session id: %v", err)
	}
	if storedID == cookieValue {
		t.Fatal("sessions.id contains the bearer-equivalent cookie value")
	}
	if storedID != hashSessionID(cookieValue) {
		t.Fatalf("sessions.id = %q, want hash %q", storedID, hashSessionID(cookieValue))
	}

	got, err := st.GetSession(ctx, cookieValue)
	if err != nil {
		t.Fatalf("GetSession(cookie): %v", err)
	}
	if got.ID != cookieValue || got.Identity.Subject != subject {
		t.Fatalf("GetSession(cookie) = %#v, want cookie value and subject preserved", got)
	}

	if err := st.DeleteSession(ctx, cookieValue); err != nil {
		t.Fatalf("DeleteSession(cookie): %v", err)
	}
	var remaining int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE subject = $1`, subject).Scan(&remaining); err != nil {
		t.Fatalf("count deleted sessions: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("sessions remaining after DeleteSession(cookie) = %d, want 0", remaining)
	}
}
