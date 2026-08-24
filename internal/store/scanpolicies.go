package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// ScanPolicy (#87, reshaped by #137) is the reusable HOW-to-scan configuration:
// a required template set (exact, all-active, or exclude mode) plus Nuclei and
// discovery knobs. The approved target is selected independently at ad-hoc
// launch or stored on a schedule. Each knob is a pointer: nil means "leave the
// built-in default for this field", so a policy can tune just one setting; the
// non-nil ones are overlaid over defaultOptions() at dispatch.
type ScanPolicy struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	TemplateSetID    string `json:"template_set_id"`
	RateLimit        *int   `json:"rate_limit,omitempty"`
	Concurrency      *int   `json:"concurrency,omitempty"`
	TimeoutSec       *int   `json:"timeout_sec,omitempty"`
	MaxHostError     *int   `json:"max_host_error,omitempty"`
	ResponseSizeRead *int   `json:"response_size_read,omitempty"`
	ResponseSizeSave *int   `json:"response_size_save,omitempty"`
	// Discovery (#86): the optional naabu port-scan pre-pass. DiscoveryEnabled is
	// a pointer so an omitted field on create means "use the column default (ON)"
	// rather than the bool zero value (off); validation resolves nil to true.
	// DiscoveryPorts empty = naabu's top-1000; DiscoveryTimeoutSec nil = the node's
	// built-in discovery default (separate from the Nuclei TimeoutSec above).
	DiscoveryEnabled *bool `json:"discovery_enabled,omitempty"`
	// DiscoveryHostDiscovery controls naabu's host-discovery pass independently of
	// its port-scan mode. nil preserves the existing SYN-on/connect-off behavior;
	// true or false applies explicitly to either mode (#133).
	DiscoveryHostDiscovery *bool `json:"discovery_host_discovery,omitempty"`
	// DiscoveryScanType picks naabu's port-scan mode ("syn"/"connect"); empty =
	// the node's NAABU_SCAN_TYPE default (#86).
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

const scanPolicyCols = `id, name, template_set_id, rate_limit, concurrency, timeout_sec, max_host_error,
	response_size_read, response_size_save,
	discovery_enabled, discovery_host_discovery, discovery_scan_type, discovery_ports, discovery_timeout_sec, discovery_rate,
	discovery_probe_timeout_ms, discovery_retries, created_by, created_at, updated_at`

// scanScanPolicy reads one row (column order must match scanPolicyCols).
func scanScanPolicy(row pgx.Row) (ScanPolicy, error) {
	var p ScanPolicy
	var discoveryScanType, discoveryPorts, createdBy *string
	err := row.Scan(&p.ID, &p.Name, &p.TemplateSetID, &p.RateLimit, &p.Concurrency, &p.TimeoutSec,
		&p.MaxHostError, &p.ResponseSizeRead, &p.ResponseSizeSave, &p.DiscoveryEnabled, &p.DiscoveryHostDiscovery, &discoveryScanType, &discoveryPorts, &p.DiscoveryTimeoutSec, &p.DiscoveryRate,
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
// template_set_id surfaces as ErrInvalidRef (FK violation).
func (s *Store) CreateScanPolicy(ctx context.Context, in ScanPolicy) (ScanPolicy, error) {
	in.ID = types.NewID()
	out, err := scanScanPolicy(s.pool.QueryRow(ctx,
		`INSERT INTO scan_policies (id, name, template_set_id, rate_limit, concurrency, timeout_sec, max_host_error,
		     response_size_read, response_size_save,
		     discovery_enabled, discovery_host_discovery, discovery_scan_type, discovery_ports, discovery_timeout_sec, discovery_rate,
		     discovery_probe_timeout_ms, discovery_retries, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10, TRUE), $11, $12, $13, $14, $15, $16, $17, $18)
		 RETURNING `+scanPolicyCols,
		in.ID, in.Name, in.TemplateSetID, in.RateLimit, in.Concurrency, in.TimeoutSec, in.MaxHostError,
		in.ResponseSizeRead, in.ResponseSizeSave,
		in.DiscoveryEnabled, in.DiscoveryHostDiscovery, nullStr(in.DiscoveryScanType), nullStr(in.DiscoveryPorts), in.DiscoveryTimeoutSec, in.DiscoveryRate,
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
		 SET name = $2, template_set_id = $3, rate_limit = $4, concurrency = $5,
		     timeout_sec = $6, max_host_error = $7, response_size_read = $8, response_size_save = $9,
		     discovery_enabled = COALESCE($10, TRUE),
		     discovery_host_discovery = $11, discovery_scan_type = $12, discovery_ports = $13, discovery_timeout_sec = $14, discovery_rate = $15,
		     discovery_probe_timeout_ms = $16, discovery_retries = $17, updated_at = now()
		 WHERE id = $1
		 RETURNING `+scanPolicyCols,
		id, in.Name, in.TemplateSetID, in.RateLimit, in.Concurrency, in.TimeoutSec, in.MaxHostError,
		in.ResponseSizeRead, in.ResponseSizeSave,
		in.DiscoveryEnabled, in.DiscoveryHostDiscovery, nullStr(in.DiscoveryScanType), nullStr(in.DiscoveryPorts), in.DiscoveryTimeoutSec, in.DiscoveryRate,
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

// DeleteScanPolicy removes a scan policy, or returns ErrNotFound. Scan history
// survives via scans.scan_policy_id ON DELETE SET NULL; schedules still cascade
// because they cannot dispatch without their selected policy.
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
