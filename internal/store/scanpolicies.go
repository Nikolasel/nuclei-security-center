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
// a required template set (including the dynamic all-active mode), and Nuclei's
// execution knobs. Every scan (ad-hoc or scheduled) is launched by selecting a
// policy. Each knob is a pointer: nil means "leave the built-in default for this
// field", so a policy can tune just one setting; the non-nil ones are overlaid
// over defaultOptions() at dispatch (see overlayScanPolicy).
type ScanPolicy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	TargetID      string `json:"target_id"`
	TemplateSetID string `json:"template_set_id"`
	RateLimit     *int   `json:"rate_limit,omitempty"`
	Concurrency   *int   `json:"concurrency,omitempty"`
	TimeoutSec    *int   `json:"timeout_sec,omitempty"`
	MaxHostError  *int   `json:"max_host_error,omitempty"`
	// Discovery (#86): the optional naabu port-scan pre-pass. DiscoveryEnabled is
	// a pointer so an omitted field on create means "use the column default (ON)"
	// rather than the bool zero value (off); validation resolves nil to true.
	// DiscoveryPorts empty = naabu's top-1000; DiscoveryTimeoutSec nil = the node's
	// built-in discovery default (separate from the Nuclei TimeoutSec above).
	DiscoveryEnabled *bool `json:"discovery_enabled,omitempty"`
	// DiscoveryScanType picks naabu's mode ("syn"/"connect"); empty = the node's
	// NAABU_SCAN_TYPE default (#86).
	DiscoveryScanType   string `json:"discovery_scan_type,omitempty"`
	DiscoveryPorts      string `json:"discovery_ports,omitempty"`
	DiscoveryTimeoutSec *int   `json:"discovery_timeout_sec,omitempty"`
	// naabu per-probe tuning (all nil = naabu's default). See DiscoveryOptions.
	DiscoveryRate           *int      `json:"discovery_rate,omitempty"`
	DiscoveryProbeTimeoutMs *int      `json:"discovery_probe_timeout_ms,omitempty"`
	DiscoveryRetries        *int      `json:"discovery_retries,omitempty"`
	CreatedBy               string    `json:"created_by,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

const scanPolicyCols = `id, name, target_id, template_set_id, rate_limit, concurrency, timeout_sec, max_host_error,
	discovery_enabled, discovery_scan_type, discovery_ports, discovery_timeout_sec, discovery_rate,
	discovery_probe_timeout_ms, discovery_retries, created_by, created_at, updated_at`

// scanScanPolicy reads one row (column order must match scanPolicyCols).
func scanScanPolicy(row pgx.Row) (ScanPolicy, error) {
	var p ScanPolicy
	var discoveryScanType, discoveryPorts, createdBy *string
	err := row.Scan(&p.ID, &p.Name, &p.TargetID, &p.TemplateSetID, &p.RateLimit, &p.Concurrency, &p.TimeoutSec,
		&p.MaxHostError, &p.DiscoveryEnabled, &discoveryScanType, &discoveryPorts, &p.DiscoveryTimeoutSec, &p.DiscoveryRate,
		&p.DiscoveryProbeTimeoutMs, &p.DiscoveryRetries, &createdBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ScanPolicy{}, ErrNotFound
		}
		return ScanPolicy{}, err
	}
	p.DiscoveryScanType = deref(discoveryScanType)
	p.DiscoveryPorts = deref(discoveryPorts)
	p.CreatedBy = deref(createdBy)
	return p, nil
}

// CreateScanPolicy inserts a scan policy and returns it populated. A bad
// target_id/template_set_id surfaces as ErrInvalidRef (FK violation).
func (s *Store) CreateScanPolicy(ctx context.Context, in ScanPolicy) (ScanPolicy, error) {
	in.ID = types.NewID()
	out, err := scanScanPolicy(s.pool.QueryRow(ctx,
		`INSERT INTO scan_policies (id, name, target_id, template_set_id, rate_limit, concurrency, timeout_sec, max_host_error,
		     discovery_enabled, discovery_scan_type, discovery_ports, discovery_timeout_sec, discovery_rate,
		     discovery_probe_timeout_ms, discovery_retries, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, TRUE), $10, $11, $12, $13, $14, $15, $16)
		 RETURNING `+scanPolicyCols,
		in.ID, in.Name, in.TargetID, in.TemplateSetID, in.RateLimit, in.Concurrency, in.TimeoutSec, in.MaxHostError,
		in.DiscoveryEnabled, nullStr(in.DiscoveryScanType), nullStr(in.DiscoveryPorts), in.DiscoveryTimeoutSec, in.DiscoveryRate,
		in.DiscoveryProbeTimeoutMs, in.DiscoveryRetries, nullStr(in.CreatedBy)))
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
		     timeout_sec = $7, max_host_error = $8, discovery_enabled = COALESCE($9, TRUE),
		     discovery_scan_type = $10, discovery_ports = $11, discovery_timeout_sec = $12, discovery_rate = $13,
		     discovery_probe_timeout_ms = $14, discovery_retries = $15, updated_at = now()
		 WHERE id = $1
		 RETURNING `+scanPolicyCols,
		id, in.Name, in.TargetID, in.TemplateSetID, in.RateLimit, in.Concurrency, in.TimeoutSec, in.MaxHostError,
		in.DiscoveryEnabled, nullStr(in.DiscoveryScanType), nullStr(in.DiscoveryPorts), in.DiscoveryTimeoutSec, in.DiscoveryRate,
		in.DiscoveryProbeTimeoutMs, in.DiscoveryRetries))
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
