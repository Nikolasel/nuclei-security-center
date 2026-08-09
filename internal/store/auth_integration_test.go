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
