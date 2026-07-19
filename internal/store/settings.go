package store

import (
	"context"
	"time"
)

// AppSettings is the single-row global settings record (#95). Today it carries
// only the scan-retention policy. ScanRetentionDays is a pointer so "unset"
// (NULL) is distinct from 0; retention is active only when RetentionEnabled is
// true AND ScanRetentionDays is a positive integer.
type AppSettings struct {
	RetentionEnabled  bool      `json:"retention_enabled"`
	ScanRetentionDays *int      `json:"scan_retention_days"`
	UpdatedBy         string    `json:"updated_by,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// RetentionActive reports whether automated scan deletion should run: enabled
// with a positive day window. Keeps the "when does the sweeper act" rule in one
// place, shared by the sweeper and (potentially) the API.
func (a AppSettings) RetentionActive() bool {
	return a.RetentionEnabled && a.ScanRetentionDays != nil && *a.ScanRetentionDays > 0
}

// GetAppSettings returns the singleton settings row. Migration 0015 seeds it, so
// this never has to synthesize a default.
func (s *Store) GetAppSettings(ctx context.Context) (AppSettings, error) {
	var a AppSettings
	var updatedBy *string
	err := s.pool.QueryRow(ctx,
		`SELECT retention_enabled, scan_retention_days, updated_by, updated_at
		   FROM app_settings WHERE id = true`).
		Scan(&a.RetentionEnabled, &a.ScanRetentionDays, &updatedBy, &a.UpdatedAt)
	if err != nil {
		return AppSettings{}, err
	}
	a.UpdatedBy = deref(updatedBy)
	return a, nil
}

// UpdateAppSettings writes the retention policy and stamps who/when, returning
// the updated row. updatedBy is the acting admin (audit-friendly provenance).
func (s *Store) UpdateAppSettings(ctx context.Context, in AppSettings, updatedBy string) (AppSettings, error) {
	var a AppSettings
	var outUpdatedBy *string
	err := s.pool.QueryRow(ctx,
		`UPDATE app_settings
		    SET retention_enabled = $1, scan_retention_days = $2,
		        updated_by = $3, updated_at = now()
		  WHERE id = true
		  RETURNING retention_enabled, scan_retention_days, updated_by, updated_at`,
		in.RetentionEnabled, in.ScanRetentionDays, nullStr(updatedBy)).
		Scan(&a.RetentionEnabled, &a.ScanRetentionDays, &outUpdatedBy, &a.UpdatedAt)
	if err != nil {
		return AppSettings{}, err
	}
	a.UpdatedBy = deref(outUpdatedBy)
	return a, nil
}

// ScansForRetention returns the ids of scans eligible for retention deletion:
// created before cutoff, in a terminal state (queued/running can't be deleted),
// and linked to a target — but never a target's single most-recent scan, so the
// lifecycle's "resolved = last-seen != target's latest scan" derivation always
// has at least one scan to compare against (docs/ARCHITECTURE.md §3). Ad-hoc
// scans (no target_id) are excluded entirely: they have no "most recent per
// target" anchor to protect, so the safe default is to leave them for manual
// deletion. Oldest first, capped at limit so one sweep can't delete without
// bound (CWE-770).
func (s *Store) ScansForRetention(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT s.id
		   FROM scans s
		  WHERE s.created_at < $1
		    AND s.state NOT IN ('queued', 'running')
		    AND s.target_id IS NOT NULL
		    AND s.id <> (
		        SELECT s2.id FROM scans s2
		         WHERE s2.target_id = s.target_id
		         ORDER BY s2.created_at DESC, s2.id DESC
		         LIMIT 1
		    )
		  ORDER BY s.created_at ASC
		  LIMIT $2`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
