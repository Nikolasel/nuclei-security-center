package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// Session is a server-side browser session. ID is the opaque cookie value;
// persistence hashes it before it reaches the database.
type Session struct {
	ID        string
	Identity  Identity
	ExpiresAt time.Time
}

// Session pagination and per-subject cap (#252).
const (
	DefaultSessionPageLimit   = 50
	MaxSessionPageLimit       = 200
	MaxLiveSessionsPerSubject = 20
)

// CreateSession stores a new session keyed by the opaque id.
// It enforces a per-subject live-session cap (#252): at most
// MaxLiveSessionsPerSubject unexpired sessions per subject are kept. When a
// subject already has MaxLiveSessionsPerSubject live sessions, the oldest live
// sessions are evicted to make room for the new one. Serialization is per
// subject via a transaction-scoped advisory lock so concurrent logins for the
// same subject cannot transiently exceed the cap.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin create session: %w", err)
	}
	defer tx.Rollback(ctx)

	// Serialize concurrent creations for the same subject.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, sess.Identity.Subject); err != nil {
		return fmt.Errorf("lock session subject: %w", err)
	}

	var live int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE subject = $1 AND expires_at > now()`, sess.Identity.Subject).Scan(&live); err != nil {
		return fmt.Errorf("count live sessions: %w", err)
	}
	if live >= MaxLiveSessionsPerSubject {
		toDelete := live - MaxLiveSessionsPerSubject + 1
		if _, err := tx.Exec(ctx,
			`DELETE FROM sessions WHERE id IN (
				SELECT id FROM sessions
				 WHERE subject = $1 AND expires_at > now()
				 ORDER BY created_at ASC, id ASC
				 LIMIT $2
			)`, sess.Identity.Subject, toDelete); err != nil {
			return fmt.Errorf("evict oldest sessions: %w", err)
		}
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO sessions (id, subject, email, name, roles, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		hashSessionID(sess.ID), sess.Identity.Subject, nullStr(sess.Identity.Email),
		nullStr(sess.Identity.Name), orEmpty(sess.Identity.Roles), sess.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit create session: %w", err)
	}
	return nil
}

// GetSession returns a live (unexpired) session by id, or ErrNotFound. Expired
// rows are treated as absent (and swept lazily elsewhere).
func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	var sess Session
	var email, name *string
	err := s.pool.QueryRow(ctx,
		`SELECT subject, email, name, roles, expires_at
		 FROM sessions WHERE id = $1 AND expires_at > now()`, hashSessionID(id),
	).Scan(&sess.Identity.Subject, &email, &name, &sess.Identity.Roles, &sess.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, err
	}
	sess.ID = id
	sess.Identity.Email = deref(email)
	sess.Identity.Name = deref(name)
	return sess, nil
}

// DeleteSession removes a session (logout). Missing is not an error.
//
// This idempotence is load-bearing for the fail-closed logout contract
// (#268): handleLogout/handleLogoutRedirect in internal/backend treat any
// non-nil error as a transient store failure and return 503 with
// Retry-After: 1 without clearing the browser cookie, so the caller can
// retry. The background SweepExpiredAuth sweeper routinely deletes expired
// sessions, so a logout for an already-swept (expired) cookie must still
// succeed with 204/200 rather than a spurious 503 from which the user could
// never complete a clean logout. Do not change this to return ErrNotFound
// for a missing row without updating the logout handlers and their tests.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, hashSessionID(id))
	return err
}

// SessionInfo is the admin-visible projection of a live session. ID is the
// stored hash (the DB primary key), not the bearer-equivalent cookie value.
type SessionInfo struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	Email     string    `json:"email,omitempty"`
	Name      string    `json:"name,omitempty"`
	Roles     []string  `json:"roles"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// sessionCursor is the opaque cursor for keyset pagination (#252).
type sessionCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func encodeSessionCursor(t time.Time, id string) string {
	b, _ := json.Marshal(sessionCursor{CreatedAt: t.UTC(), ID: id})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeSessionCursor(s string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor: %w", err)
	}
	var c sessionCursor
	if err := json.Unmarshal(b, &c); err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor: %w", err)
	}
	if c.ID == "" {
		return time.Time{}, "", fmt.Errorf("invalid cursor: missing id")
	}
	if c.CreatedAt.IsZero() {
		return time.Time{}, "", fmt.Errorf("invalid cursor: missing created_at")
	}
	return c.CreatedAt, c.ID, nil
}

// escapeLikeSession escapes LIKE metacharacters for session search (#211).
func escapeLikeSession(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// clampSessionLimit enforces the server ceiling for session pagination.
func clampSessionLimit(limit int) int {
	if limit <= 0 || limit > MaxSessionPageLimit {
		return DefaultSessionPageLimit
	}
	return limit
}

// ListSessions returns a keyset-paginated view of live (unexpired) sessions for
// admin inspection (#252). It enforces a hard page-size ceiling, supports an
// optional case-insensitive substring filter `q` (matches subject/email/name/roles),
// and uses a stable cursor over (created_at DESC, id DESC) so concurrent
// revocations/expirations do not cause skipped rows. The cursor is an opaque
// base64-encoded JSON token; an empty cursor starts from the newest row.
// Results are ordered by created_at DESC, id DESC (unique tie-breaker) and the
// method returns the next cursor (empty when at the end) plus the total count of
// live sessions matching the filter (before cursor/limit).
func (s *Store) ListSessions(ctx context.Context, limit int, cursor string, q string) ([]SessionInfo, string, int, error) {
	limit = clampSessionLimit(limit)
	q = strings.TrimSpace(q)
	var pattern string
	var hasFilter bool
	if q != "" {
		pattern = "%" + escapeLikeSession(q) + "%"
		hasFilter = true
	}

	// Total count for the filtered set (without cursor).
	var total int
	if hasFilter {
		if err := s.pool.QueryRow(ctx,
			`SELECT count(*) FROM sessions WHERE expires_at > now() AND (subject ILIKE $1 ESCAPE '\' OR email ILIKE $1 ESCAPE '\' OR name ILIKE $1 ESCAPE '\' OR array_to_string(roles, ' ') ILIKE $1 ESCAPE '\')`,
			pattern).Scan(&total); err != nil {
			return nil, "", 0, err
		}
	} else {
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE expires_at > now()`).Scan(&total); err != nil {
			return nil, "", 0, err
		}
	}

	// Build keyset query.
	args := []any{}
	where := "WHERE expires_at > now()"
	if hasFilter {
		where += fmt.Sprintf(" AND (subject ILIKE $%d ESCAPE '\\' OR email ILIKE $%d ESCAPE '\\' OR name ILIKE $%d ESCAPE '\\' OR array_to_string(roles, ' ') ILIKE $%d ESCAPE '\\')", len(args)+1, len(args)+1, len(args)+1, len(args)+1)
		args = append(args, pattern)
	}
	if cursor != "" {
		ct, cid, err := decodeSessionCursor(cursor)
		if err != nil {
			return nil, "", 0, err
		}
		where += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d)", len(args)+1, len(args)+2)
		args = append(args, ct, cid)
	}
	where += " ORDER BY created_at DESC, id DESC"
	// Fetch one extra row to detect hasMore.
	args = append(args, limit+1)
	query := fmt.Sprintf(`SELECT id, subject, email, name, roles, created_at, expires_at FROM sessions %s LIMIT $%d`, where, len(args))
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()
	var out []SessionInfo
	for rows.Next() {
		var si SessionInfo
		var email, name *string
		if err := rows.Scan(&si.ID, &si.Subject, &email, &name, &si.Roles, &si.CreatedAt, &si.ExpiresAt); err != nil {
			return nil, "", 0, err
		}
		si.Email = deref(email)
		si.Name = deref(name)
		if si.Roles == nil {
			si.Roles = []string{}
		}
		out = append(out, si)
	}
	if err := rows.Err(); err != nil {
		return nil, "", 0, err
	}
	if out == nil {
		out = []SessionInfo{}
	}
	var nextCursor string
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		nextCursor = encodeSessionCursor(last.CreatedAt, last.ID)
	}
	return out, nextCursor, total, nil
}

// ListSessionsOffset is the legacy offset-paginated view retained only as a
// compatibility shim for rolling clients that still send `?offset=` (#252).
// New clients must use ListSessions with a cursor. It enforces the same
// limit ceiling, filter, and unique ordering (created_at DESC, id DESC) but
// retains OFFSET semantics and therefore still recomputes the mutable
// expires_at set on each page. It exists solely so a cached SPA that still
// sends offset continues to paginate until it reloads the new cursor-aware
// bundle.
func (s *Store) ListSessionsOffset(ctx context.Context, limit, offset int, q string) ([]SessionInfo, int, error) {
	limit = clampSessionLimit(limit)
	if offset < 0 {
		offset = 0
	}
	q = strings.TrimSpace(q)
	var pattern string
	var hasFilter bool
	if q != "" {
		pattern = "%" + escapeLikeSession(q) + "%"
		hasFilter = true
	}
	var total int
	if hasFilter {
		if err := s.pool.QueryRow(ctx,
			`SELECT count(*) FROM sessions WHERE expires_at > now() AND (subject ILIKE $1 ESCAPE '\' OR email ILIKE $1 ESCAPE '\' OR name ILIKE $1 ESCAPE '\' OR array_to_string(roles, ' ') ILIKE $1 ESCAPE '\')`,
			pattern).Scan(&total); err != nil {
			return nil, 0, err
		}
	} else {
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE expires_at > now()`).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	args := []any{}
	where := "WHERE expires_at > now()"
	if hasFilter {
		where += fmt.Sprintf(" AND (subject ILIKE $%d ESCAPE '\\' OR email ILIKE $%d ESCAPE '\\' OR name ILIKE $%d ESCAPE '\\' OR array_to_string(roles, ' ') ILIKE $%d ESCAPE '\\')", len(args)+1, len(args)+1, len(args)+1, len(args)+1)
		args = append(args, pattern)
	}
	where += " ORDER BY created_at DESC, id DESC"
	args = append(args, limit)
	args = append(args, offset)
	query := fmt.Sprintf(`SELECT id, subject, email, name, roles, created_at, expires_at FROM sessions %s LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args))
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []SessionInfo
	for rows.Next() {
		var si SessionInfo
		var email, name *string
		if err := rows.Scan(&si.ID, &si.Subject, &email, &name, &si.Roles, &si.CreatedAt, &si.ExpiresAt); err != nil {
			return nil, 0, err
		}
		si.Email = deref(email)
		si.Name = deref(name)
		if si.Roles == nil {
			si.Roles = []string{}
		}
		out = append(out, si)
	}
	if out == nil {
		out = []SessionInfo{}
	}
	return out, total, rows.Err()
}

// DeleteSessionByID removes a session by its stored hashed ID (admin
// revocation). Unlike DeleteSession, the argument is not hashed again.
func (s *Store) DeleteSessionByID(ctx context.Context, hashedID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, hashedID)
	return err
}

// DeleteSessionsBySubject removes every live session for a subject (user
// offboarding / role revocation). It returns the number of rows deleted.
func (s *Store) DeleteSessionsBySubject(ctx context.Context, subject string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE subject = $1`, subject)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func hashSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
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

// ErrAuthFlowLimit means the bounded live authorization-flow pool is full. It
// is an expected admission result, not a database failure; callers should ask
// the browser/client to retry later without exposing internal details.
var ErrAuthFlowLimit = errors.New("authorization flow limit reached")

// ErrAuthFlowBusy means another backend is currently admitting an auth flow.
// It is an expected, retryable admission result rather than a database fault.
var ErrAuthFlowBusy = errors.New("authorization flow admission busy")

const (
	authFlowAdmissionKey        = int64(0x6e73632d61757468) // "nsc-auth"
	authFlowAdmissionAttempts   = 3
	authFlowAdmissionRetryDelay = 5 * time.Millisecond
)

// CreateAuthFlow stores per-login state before redirecting to the IdP. Creation
// is globally bounded across backend replicas. A non-blocking transaction
// advisory-lock probe provides the linearization point without queueing a pool
// connection behind another login. The live-row count uses the expiry index;
// physical deletion belongs to the background sweeper.
func (s *Store) CreateAuthFlow(ctx context.Context, f AuthFlow) error {
	maxLive := s.maxLiveAuthFlows
	if maxLive <= 0 {
		maxLive = DefaultMaxLiveAuthFlows
	}
	return s.createAuthFlowWithLimit(ctx, f, maxLive)
}

func (s *Store) createAuthFlowWithLimit(ctx context.Context, f AuthFlow, maxLive int) error {
	return retryAuthFlowAdmission(ctx, func() error {
		return s.createAuthFlowAttempt(ctx, f, maxLive)
	})
}

func retryAuthFlowAdmission(ctx context.Context, attempt func() error) error {
	for attemptNumber := 0; attemptNumber < authFlowAdmissionAttempts; attemptNumber++ {
		err := attempt()
		if !errors.Is(err, ErrAuthFlowBusy) || attemptNumber == authFlowAdmissionAttempts-1 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(authFlowAdmissionRetryDelay):
		}
	}
	return nil
}

func (s *Store) createAuthFlowAttempt(ctx context.Context, f AuthFlow, maxLive int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin auth flow admission transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var acquired bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, authFlowAdmissionKey).Scan(&acquired); err != nil {
		return fmt.Errorf("probe auth flow admission lock: %w", err)
	}
	if !acquired {
		return ErrAuthFlowBusy
	}
	var live int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM auth_flows WHERE expires_at > now()`).Scan(&live); err != nil {
		return fmt.Errorf("count live auth flows: %w", err)
	}
	if live >= maxLive {
		return ErrAuthFlowLimit
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO auth_flows (state, nonce, pkce_verifier, return_to, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		f.State, f.Nonce, f.PKCEVerifier, nullStr(f.ReturnTo), f.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert auth flow: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit auth flow: %w", err)
	}
	return nil
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
