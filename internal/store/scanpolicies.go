package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// ScanPolicy (#87) is the central, reusable scan configuration: it bundles
// EVERYTHING a scan needs — the target to scan (TargetID, required — the scope),
// an optional template set (TemplateSetID, empty = all templates), and Nuclei's
// execution knobs. Every scan (ad-hoc or scheduled) is launched by selecting a
// policy. Each knob is a pointer: nil means "leave the built-in default for this
// field", so a policy can tune just one setting; the non-nil ones are overlaid
// over defaultOptions() at dispatch (see overlayScanPolicy).
type ScanPolicy struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	TargetID      string    `json:"target_id"`
	TemplateSetID string    `json:"template_set_id,omitempty"`
	RateLimit     *int      `json:"rate_limit,omitempty"`
	Concurrency   *int      `json:"concurrency,omitempty"`
	TimeoutSec    *int      `json:"timeout_sec,omitempty"`
	MaxHostError  *int      `json:"max_host_error,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

const scanPolicyCols = `id, name, target_id, template_set_id, rate_limit, concurrency, timeout_sec, max_host_error,
	created_by, created_at, updated_at`

// scanScanPolicy reads one row (column order must match scanPolicyCols).
func scanScanPolicy(row pgx.Row) (ScanPolicy, error) {
	var p ScanPolicy
	var templateSetID, createdBy *string
	err := row.Scan(&p.ID, &p.Name, &p.TargetID, &templateSetID, &p.RateLimit, &p.Concurrency, &p.TimeoutSec,
		&p.MaxHostError, &createdBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ScanPolicy{}, ErrNotFound
		}
		return ScanPolicy{}, err
	}
	p.TemplateSetID = deref(templateSetID)
	p.CreatedBy = deref(createdBy)
	return p, nil
}

// CreateScanPolicy inserts a scan policy and returns it populated. A bad
// target_id/template_set_id surfaces as ErrInvalidRef (FK violation).
func (s *Store) CreateScanPolicy(ctx context.Context, in ScanPolicy) (ScanPolicy, error) {
	in.ID = types.NewID()
	out, err := scanScanPolicy(s.pool.QueryRow(ctx,
		`INSERT INTO scan_policies (id, name, target_id, template_set_id, rate_limit, concurrency, timeout_sec, max_host_error, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING `+scanPolicyCols,
		in.ID, in.Name, in.TargetID, nullStr(in.TemplateSetID), in.RateLimit, in.Concurrency, in.TimeoutSec, in.MaxHostError, nullStr(in.CreatedBy)))
	if err != nil {
		if isUniqueViolation(err) {
			return ScanPolicy{}, ErrConflict
		}
		if isForeignKeyViolation(err) {
			return ScanPolicy{}, ErrInvalidRef
		}
		return ScanPolicy{}, fmt.Errorf("insert scan policy: %w", err)
	}
	return out, nil
}

// GetScanPolicy returns one scan policy by id, or ErrNotFound.
func (s *Store) GetScanPolicy(ctx context.Context, id string) (ScanPolicy, error) {
	return scanScanPolicy(s.pool.QueryRow(ctx,
		`SELECT `+scanPolicyCols+` FROM scan_policies WHERE id = $1`, id))
}

// ListScanPolicies returns all scan policies ordered by name.
func (s *Store) ListScanPolicies(ctx context.Context) ([]ScanPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scanPolicyCols+` FROM scan_policies ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanPolicy
	for rows.Next() {
		p, err := scanScanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateScanPolicy updates mutable fields and returns the fresh row.
func (s *Store) UpdateScanPolicy(ctx context.Context, id string, in ScanPolicy) (ScanPolicy, error) {
	out, err := scanScanPolicy(s.pool.QueryRow(ctx,
		`UPDATE scan_policies
		 SET name = $2, target_id = $3, template_set_id = $4, rate_limit = $5, concurrency = $6,
		     timeout_sec = $7, max_host_error = $8, updated_at = now()
		 WHERE id = $1
		 RETURNING `+scanPolicyCols,
		id, in.Name, in.TargetID, nullStr(in.TemplateSetID), in.RateLimit, in.Concurrency, in.TimeoutSec, in.MaxHostError))
	if err != nil {
		if isUniqueViolation(err) {
			return ScanPolicy{}, ErrConflict
		}
		if isForeignKeyViolation(err) {
			return ScanPolicy{}, ErrInvalidRef
		}
		return ScanPolicy{}, err
	}
	return out, nil
}

// DeleteScanPolicy removes a scan policy, or returns ErrNotFound. The scans/
// schedules FK is ON DELETE SET NULL, so history and schedules survive; affected
// dispatches simply fall back to the built-in defaults.
func (s *Store) DeleteScanPolicy(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scan_policies WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
