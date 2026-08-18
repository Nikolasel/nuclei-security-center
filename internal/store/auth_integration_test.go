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

func TestCreateAuthFlowAdmissionIgnoresExpiredRowsAndEnforcesLimitPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	expired := AuthFlow{
		State:        "expired-" + types.NewID(),
		Nonce:        "nonce",
		PKCEVerifier: "verifier",
		ExpiresAt:    time.Now().Add(-time.Minute),
	}
	if err := st.createAuthFlowWithLimit(ctx, expired, 1); err != nil {
		t.Fatalf("create expired auth flow: %v", err)
	}

	active := AuthFlow{
		State:        "active-" + types.NewID(),
		Nonce:        "nonce",
		PKCEVerifier: "verifier",
		ExpiresAt:    time.Now().Add(time.Minute),
	}
	if err := st.createAuthFlowWithLimit(ctx, active, 1); err != nil {
		t.Fatalf("create active auth flow: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO auth_flows (state, nonce, pkce_verifier, expires_at)
		VALUES ($1, 'nonce', 'verifier', now() - interval '1 minute')`,
		"expired-again-"+types.NewID()); err != nil {
		t.Fatalf("insert expired auth flow at capacity: %v", err)
	}

	second := AuthFlow{
		State:        "second-" + types.NewID(),
		Nonce:        "nonce",
		PKCEVerifier: "verifier",
		ExpiresAt:    time.Now().Add(time.Minute),
	}
	if err := st.createAuthFlowWithLimit(ctx, second, 1); !errors.Is(err, ErrAuthFlowLimit) {
		t.Fatalf("second active auth flow error = %v, want ErrAuthFlowLimit", err)
	}

	var expiredCount, activeCount, remainingExpired int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM auth_flows WHERE state = $1`, expired.State).Scan(&expiredCount); err != nil {
		t.Fatalf("count expired auth flow: %v", err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM auth_flows WHERE state = $1`, active.State).Scan(&activeCount); err != nil {
		t.Fatalf("count active auth flow: %v", err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM auth_flows WHERE expires_at <= now()`).Scan(&remainingExpired); err != nil {
		t.Fatalf("count remaining expired auth flows: %v", err)
	}
	if expiredCount != 1 || activeCount != 1 || remainingExpired != 2 {
		t.Fatalf("auth flow counts expired=%d active=%d remaining_expired=%d, want 1/1/2", expiredCount, activeCount, remainingExpired)
	}
}

func TestAuthFlowExpiryIndexExistsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	var exists bool
	if err := st.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM pg_indexes
			 WHERE schemaname = current_schema()
			   AND tablename = 'auth_flows'
			   AND indexname = 'auth_flows_expires_at_idx'
		)`).Scan(&exists); err != nil {
		t.Fatalf("inspect auth flow expiry index: %v", err)
	}
	if !exists {
		t.Fatal("auth_flows_expires_at_idx is missing")
	}
}

func TestCreateAuthFlowAdmissionBoundsConcurrentLimitPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			<-start
			results <- st.createAuthFlowWithLimit(ctx, AuthFlow{
				State:        "concurrent-" + types.NewID(),
				Nonce:        "nonce",
				PKCEVerifier: "verifier",
				ExpiresAt:    time.Now().Add(time.Minute),
			}, 1)
		}(i)
	}
	close(start)

	successes, limited, busy := 0, 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrAuthFlowLimit):
			limited++
		case errors.Is(err, ErrAuthFlowBusy):
			busy++
		default:
			t.Fatalf("concurrent auth-flow admission error = %v", err)
		}
	}
	if successes != 1 || limited+busy != 1 {
		t.Fatalf("concurrent auth-flow results successes=%d limited=%d busy=%d, want 1 and one bounded rejection", successes, limited, busy)
	}
}

func TestCreateAuthFlowAdmissionDoesNotWaitForHeldLockPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	conn, err := st.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire lock connection: %v", err)
	}
	defer conn.Release()
	lockTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock transaction: %v", err)
	}
	defer lockTx.Rollback(ctx)
	if _, err := lockTx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, authFlowAdmissionKey); err != nil {
		t.Fatalf("hold auth-flow admission lock: %v", err)
	}

	attemptCtx, attemptCancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer attemptCancel()
	err = st.createAuthFlowWithLimit(attemptCtx, AuthFlow{
		State:        "busy-" + types.NewID(),
		Nonce:        "nonce",
		PKCEVerifier: "verifier",
		ExpiresAt:    time.Now().Add(time.Minute),
	}, 1)
	if !errors.Is(err, ErrAuthFlowBusy) {
		t.Fatalf("held-lock admission error = %v, want ErrAuthFlowBusy", err)
	}
}
