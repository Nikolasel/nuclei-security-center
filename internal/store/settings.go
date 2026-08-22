package store

import (
	"context"
	"time"
)

// MaxScanRetentionDays is the inclusive upper bound for the retention window.
// 36500 = 100 years, comfortably above any operational need but well below the
// ~106752-day int64-nanosecond overflow threshold (CWE-190, #192).
const MaxScanRetentionDays = 36500

// AppSettings is the single-row global settings record (#95). Today it carries
// only the scan-retention policy. ScanRetentionDays is a pointer so "unset"
// (NULL) is distinct from 0; retention is active only when RetentionEnabled is
// true AND ScanRetentionDays is a valid window within [1, MaxScanRetentionDays].
type AppSettings struct {
	RetentionEnabled      bool      `json:"retention_enabled"`
	ScanRetentionDays     *int      `json:"scan_retention_days"`
	RetentionIncludeAdhoc bool      `json:"retention_include_adhoc"`
	UpdatedBy             string    `json:"updated_by,omitempty"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// RetentionActive reports whether automated scan deletion should run: enabled
// with a valid day window. Keeps the "when does the sweeper act" rule in one
// place, shared by the sweeper and (potentially) the API.
func (a AppSettings) RetentionActive() bool {
	return a.RetentionEnabled && a.ScanRetentionDays != nil && *a.ScanRetentionDays > 0 && *a.ScanRetentionDays <= MaxScanRetentionDays
}

// RetentionCutoff returns the exclusive age cutoff for retention: scans with
// created_at < cutoff are eligible. It uses calendar arithmetic (AddDate) so the
// conversion cannot overflow int64 nanoseconds (CWE-190, #192), and it fails
// closed by returning a zero time when the window is not active or invalid.
// Callers must not issue a retention query when the returned cutoff is zero or
// not in the past.
func (a AppSettings) RetentionCutoff(now time.Time) time.Time {
	if !a.RetentionActive() {
		return time.Time{}
	}
	return now.AddDate(0, 0, -*a.ScanRetentionDays)
}

// GetAppSettings returns the singleton settings row. The baseline seeds it, so
// this never has to synthesize a default.
func (s *Store) GetAppSettings(ctx context.Context) (AppSettings, error) {
	var a AppSettings
	var updatedBy *string
	err := s.pool.QueryRow(ctx,
		`SELECT retention_enabled, scan_retention_days, retention_include_adhoc, updated_by, updated_at
		   FROM app_settings WHERE id = true`).
		Scan(&a.RetentionEnabled, &a.ScanRetentionDays, &a.RetentionIncludeAdhoc, &updatedBy, &a.UpdatedAt)
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
		    SET retention_enabled = $1, scan_retention_days = $2, retention_include_adhoc = $3,
		        updated_by = $4, updated_at = now()
		  WHERE id = true
		  RETURNING retention_enabled, scan_retention_days, retention_include_adhoc, updated_by, updated_at`,
		in.RetentionEnabled, in.ScanRetentionDays, in.RetentionIncludeAdhoc, nullStr(updatedBy)).
		Scan(&a.RetentionEnabled, &a.ScanRetentionDays, &a.RetentionIncludeAdhoc, &outUpdatedBy, &a.UpdatedAt)
	if err != nil {
		return AppSettings{}, err
	}
	a.UpdatedBy = deref(outUpdatedBy)
	return a, nil
}

// ScansForRetention returns the ids of scans eligible for retention deletion:
// created before cutoff and in a terminal state (queued/running can't be
// deleted). A target-linked scan is never a target's single most-recent scan, so
// the lifecycle's "resolved = last-seen != target's latest scan" derivation
// always has at least one scan to compare against (docs/ARCHITECTURE.md §3).
//
// Ad-hoc scans (no target_id) are included only when includeAdhoc is true, and
// then swept purely on age with no most-recent exception: ad-hoc findings always
// derive as "active" (the latest-scan comparison is gated on a non-null target),
// and store.DeleteScan's lifecycle repair deletes any now-evidence-free rows, so
// nothing is left stale even if every ad-hoc scan goes.
//
// Oldest first, capped at limit so one sweep can't delete without bound (CWE-770).
func (s *Store) ScansForRetention(ctx context.Context, cutoff time.Time, includeAdhoc bool, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT s.id
		   FROM scans s
		  WHERE s.created_at < $1
		    AND s.state NOT IN ('queued', 'running')
		    AND ($2 OR s.target_id IS NOT NULL)
		    AND (
		        s.target_id IS NULL  -- ad-hoc (only reachable when $2): no anchor to keep
		        OR s.id <> (
		            SELECT s2.id FROM scans s2
		             WHERE s2.target_id = s.target_id
		             ORDER BY s2.created_at DESC, s2.id DESC
		             LIMIT 1
		        )
		    )
		  ORDER BY s.created_at ASC
		  LIMIT $3`, cutoff, includeAdhoc, limit)
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
