package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Identity is who a request is acting as, derived from the OIDC session. Roles
// come from the IdP (a groups/roles claim), not from local assignment.
type Identity struct {
	Subject string   `json:"subject"`
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Roles   []string `json:"roles"`
}

// UpsertUser records (or refreshes) the identity registry row for a subject on
// login and returns the user id. Authorization never reads this row — it exists
// for audit and to give created_by a stable handle.
func (s *Store) UpsertUser(ctx context.Context, id Identity) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, subject, email, name, roles, last_login_at)
		 VALUES ($1, $2, $3, $4, $5, now())
		 ON CONFLICT (subject) DO UPDATE
		   SET email = EXCLUDED.email,
		       name = EXCLUDED.name,
		       roles = EXCLUDED.roles,
		       last_login_at = now()`,
		types.NewID(), id.Subject, nullStr(id.Email), nullStr(id.Name), orEmpty(id.Roles),
	)
	return err
}

// Session is a server-side browser session. ID is the opaque cookie value.
type Session struct {
	ID        string
	Identity  Identity
	ExpiresAt time.Time
}

// CreateSession stores a new session keyed by the opaque id.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id, subject, email, name, roles, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		sess.ID, sess.Identity.Subject, nullStr(sess.Identity.Email),
		nullStr(sess.Identity.Name), orEmpty(sess.Identity.Roles), sess.ExpiresAt,
	)
	return err
}

// GetSession returns a live (unexpired) session by id, or ErrNotFound. Expired
// rows are treated as absent (and swept lazily elsewhere).
func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	var sess Session
	var email, name *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, subject, email, name, roles, expires_at
		 FROM sessions WHERE id = $1 AND expires_at > now()`, id,
	).Scan(&sess.ID, &sess.Identity.Subject, &email, &name, &sess.Identity.Roles, &sess.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, err
	}
	sess.Identity.Email = deref(email)
	sess.Identity.Name = deref(name)
	return sess, nil
}

// DeleteSession removes a session (logout). Missing is not an error.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

// AuthFlow is transient authorization-code-flow state, keyed by the opaque
// state parameter (which doubles as CSRF protection).
type AuthFlow struct {
	State        string
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
	ExpiresAt    time.Time
}

// CreateAuthFlow stores per-login state before redirecting to the IdP.
func (s *Store) CreateAuthFlow(ctx context.Context, f AuthFlow) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_flows (state, nonce, pkce_verifier, return_to, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		f.State, f.Nonce, f.PKCEVerifier, nullStr(f.ReturnTo), f.ExpiresAt,
	)
	return err
}

// TakeAuthFlow atomically consumes a live auth flow by state (single-use), or
// returns ErrNotFound if it's unknown, already used, or expired.
func (s *Store) TakeAuthFlow(ctx context.Context, state string) (AuthFlow, error) {
	var f AuthFlow
	var returnTo *string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM auth_flows
		 WHERE state = $1 AND expires_at > now()
		 RETURNING state, nonce, pkce_verifier, return_to, expires_at`, state,
	).Scan(&f.State, &f.Nonce, &f.PKCEVerifier, &returnTo, &f.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuthFlow{}, ErrNotFound
		}
		return AuthFlow{}, err
	}
	f.ReturnTo = deref(returnTo)
	return f, nil
}

// SweepExpiredAuth deletes expired sessions and auth flows. Cheap housekeeping
// run on an interval; best-effort.
func (s *Store) SweepExpiredAuth(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM auth_flows WHERE expires_at <= now()`)
	return err
}
