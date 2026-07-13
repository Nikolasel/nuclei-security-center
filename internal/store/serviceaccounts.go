package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// ServiceAccount is an NSC-local identity for headless/automation callers (#70).
// It carries a single role (the same RBAC the session cookie uses) and
// authenticates with a bearer token whose hash is all that's stored — the token
// itself is returned to the operator once, at creation/rotation, and never again.
type ServiceAccount struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	TokenPrefix string     `json:"token_prefix"`
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// CreateServiceAccount inserts a service account with the given token hash and
// prefix, returning it with server-set fields populated. expiresAt is nil for no
// expiry. A duplicate name yields ErrConflict.
func (s *Store) CreateServiceAccount(ctx context.Context, sa ServiceAccount, tokenHash string, expiresAt *time.Time) (ServiceAccount, error) {
	sa.ID = types.NewID()
	sa.ExpiresAt = expiresAt
	err := s.pool.QueryRow(ctx,
		`INSERT INTO service_accounts (id, name, role, token_hash, token_prefix, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING created_at`,
		sa.ID, sa.Name, sa.Role, tokenHash, sa.TokenPrefix, nullStr(sa.CreatedBy), expiresAt,
	).Scan(&sa.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ServiceAccount{}, ErrConflict
		}
		return ServiceAccount{}, fmt.Errorf("insert service account: %w", err)
	}
	return sa, nil
}

// ListServiceAccounts returns all service accounts (never the token), newest first.
func (s *Store) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, role, token_prefix, created_by, created_at, expires_at, last_used_at
		 FROM service_accounts ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	defer rows.Close()

	out := []ServiceAccount{}
	for rows.Next() {
		var sa ServiceAccount
		var createdBy *string
		if err := rows.Scan(&sa.ID, &sa.Name, &sa.Role, &sa.TokenPrefix, &createdBy,
			&sa.CreatedAt, &sa.ExpiresAt, &sa.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan service account: %w", err)
		}
		sa.CreatedBy = deref(createdBy)
		out = append(out, sa)
	}
	return out, rows.Err()
}

// RotateServiceAccountToken replaces a service account's token hash + prefix and
// resets its expiry, invalidating the previous token. ErrNotFound if unknown.
func (s *Store) RotateServiceAccountToken(ctx context.Context, id, tokenHash, tokenPrefix string, expiresAt *time.Time) (ServiceAccount, error) {
	var sa ServiceAccount
	var createdBy *string
	err := s.pool.QueryRow(ctx,
		`UPDATE service_accounts
		    SET token_hash = $2, token_prefix = $3, expires_at = $4, last_used_at = NULL
		  WHERE id = $1
		 RETURNING id, name, role, token_prefix, created_by, created_at, expires_at, last_used_at`,
		id, tokenHash, tokenPrefix, expiresAt,
	).Scan(&sa.ID, &sa.Name, &sa.Role, &sa.TokenPrefix, &createdBy,
		&sa.CreatedAt, &sa.ExpiresAt, &sa.LastUsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ServiceAccount{}, ErrNotFound
		}
		return ServiceAccount{}, fmt.Errorf("rotate service account: %w", err)
	}
	sa.CreatedBy = deref(createdBy)
	return sa, nil
}

// DeleteServiceAccount removes a service account, immediately revoking its token.
// ErrNotFound if it doesn't exist.
func (s *Store) DeleteServiceAccount(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM service_accounts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateServiceAccount resolves a token hash to the account's identity,
// enforcing revocation (row absent) and expiry. It returns the identity and the
// account id (for a last-used touch), or ErrNotFound when no live account matches.
func (s *Store) AuthenticateServiceAccount(ctx context.Context, tokenHash string) (Identity, string, error) {
	var id, name, role string
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, role FROM service_accounts
		  WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now())`,
		tokenHash,
	).Scan(&id, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Identity{}, "", ErrNotFound
		}
		return Identity{}, "", err
	}
	// Subject uses an "svc:" prefix so a service account is a visibly distinct
	// actor in the audit log, never conflatable with a human OIDC subject.
	return Identity{Subject: "svc:" + name, Name: name, Roles: []string{role}}, id, nil
}

// TouchServiceAccount records that a token was just used. Best-effort: callers
// ignore the error since it must never fail an otherwise-valid request.
func (s *Store) TouchServiceAccount(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE service_accounts SET last_used_at = now() WHERE id = $1`, id)
	return err
}
