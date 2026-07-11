package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Target is a named set of hosts a scan may run against. Its Hosts list is the
// scope allowlist (§6 of the architecture doc).
type Target struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hosts     []string  `json:"hosts"`
	Tags      []string  `json:"tags"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateTarget inserts a target and returns it with server-set fields populated.
func (s *Store) CreateTarget(ctx context.Context, in Target) (Target, error) {
	in.ID = types.NewID()
	in.Tags = orEmpty(in.Tags)
	err := s.pool.QueryRow(ctx,
		`INSERT INTO targets (id, name, hosts, tags, created_by)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING created_at, updated_at`,
		in.ID, in.Name, in.Hosts, in.Tags, nullStr(in.CreatedBy),
	).Scan(&in.CreatedAt, &in.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Target{}, ErrConflict
		}
		return Target{}, fmt.Errorf("insert target: %w", err)
	}
	return in, nil
}

// GetTarget returns one target by id, or ErrNotFound.
func (s *Store) GetTarget(ctx context.Context, id string) (Target, error) {
	var t Target
	var createdBy *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, hosts, tags, created_by, created_at, updated_at
		 FROM targets WHERE id = $1`, id,
	).Scan(&t.ID, &t.Name, &t.Hosts, &t.Tags, &createdBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Target{}, ErrNotFound
		}
		return Target{}, err
	}
	t.CreatedBy = deref(createdBy)
	return t, nil
}

// ListTargets returns all targets ordered by name.
func (s *Store) ListTargets(ctx context.Context) ([]Target, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, hosts, tags, created_by, created_at, updated_at
		 FROM targets ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Target
	for rows.Next() {
		var t Target
		var createdBy *string
		if err := rows.Scan(&t.ID, &t.Name, &t.Hosts, &t.Tags, &createdBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.CreatedBy = deref(createdBy)
		out = append(out, t)
	}
	return out, rows.Err()
}

// AllTargetHosts returns the union of every target's hosts — the approved-scope
// allowlist a scan's targets must fall inside (§6). Order is unspecified and
// duplicates are possible; callers treat it as a set.
func (s *Store) AllTargetHosts(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT hosts FROM targets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var hosts []string
		if err := rows.Scan(&hosts); err != nil {
			return nil, err
		}
		out = append(out, hosts...)
	}
	return out, rows.Err()
}

// UpdateTarget updates a target's mutable fields and returns the fresh row.
func (s *Store) UpdateTarget(ctx context.Context, id string, in Target) (Target, error) {
	in.Tags = orEmpty(in.Tags)
	var createdBy *string
	err := s.pool.QueryRow(ctx,
		`UPDATE targets SET name = $2, hosts = $3, tags = $4, updated_at = now()
		 WHERE id = $1
		 RETURNING id, name, hosts, tags, created_by, created_at, updated_at`,
		id, in.Name, in.Hosts, in.Tags,
	).Scan(&in.ID, &in.Name, &in.Hosts, &in.Tags, &createdBy, &in.CreatedAt, &in.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Target{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return Target{}, ErrConflict
		}
		return Target{}, fmt.Errorf("update target: %w", err)
	}
	in.CreatedBy = deref(createdBy)
	return in, nil
}

// DeleteTarget removes a target, or returns ErrNotFound.
func (s *Store) DeleteTarget(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM targets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- small shared helpers for the CRUD layer ---

// isUniqueViolation reports whether err is a Postgres unique-constraint error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isForeignKeyViolation reports whether err is a Postgres FK-constraint error —
// e.g. a schedule referencing a target/template set that doesn't exist.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// nullStr maps "" to a SQL NULL so optional TEXT columns stay NULL, not empty.
func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// orEmpty guarantees a non-nil slice so pgx encodes '{}' (NOT NULL columns).
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
