package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Schedule ties a target (+ optional template set) to a cron expression. The
// backend ticker dispatches schedules whose NextRunAt has arrived; cron parsing
// and NextRunAt computation live in the backend layer, so this struct just
// stores the results. LastScanID/LastRunAt record the most recent dispatch.
type Schedule struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	TargetID      string     `json:"target_id"`
	TemplateSetID string     `json:"template_set_id,omitempty"`
	Cron          string     `json:"cron"`
	Enabled       bool       `json:"enabled"`
	NextRunAt     *time.Time `json:"next_run_at,omitempty"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastScanID    string     `json:"last_scan_id,omitempty"`
	CreatedBy     string     `json:"created_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

const scheduleCols = `id, name, target_id, template_set_id, cron, enabled,
	next_run_at, last_run_at, last_scan_id, created_by, created_at, updated_at`

// scanSchedule reads one schedule row (column order must match scheduleCols).
func scanSchedule(row pgx.Row) (Schedule, error) {
	var s Schedule
	var templateSetID, lastScanID, createdBy *string
	err := row.Scan(&s.ID, &s.Name, &s.TargetID, &templateSetID, &s.Cron, &s.Enabled,
		&s.NextRunAt, &s.LastRunAt, &lastScanID, &createdBy, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return Schedule{}, err
	}
	s.TemplateSetID = deref(templateSetID)
	s.LastScanID = deref(lastScanID)
	s.CreatedBy = deref(createdBy)
	return s, nil
}

// CreateSchedule inserts a schedule. NextRunAt is computed by the caller (the
// backend, which owns the cron parser) so no cron logic lives in the store.
func (s *Store) CreateSchedule(ctx context.Context, in Schedule) (Schedule, error) {
	in.ID = types.NewID()
	row := s.pool.QueryRow(ctx,
		`INSERT INTO schedules (id, name, target_id, template_set_id, cron, enabled, next_run_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING `+scheduleCols,
		in.ID, in.Name, in.TargetID, nullStr(in.TemplateSetID), in.Cron, in.Enabled,
		in.NextRunAt, nullStr(in.CreatedBy),
	)
	out, err := scanSchedule(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Schedule{}, ErrConflict
		}
		if isForeignKeyViolation(err) {
			return Schedule{}, ErrInvalidRef
		}
		return Schedule{}, fmt.Errorf("insert schedule: %w", err)
	}
	return out, nil
}

// GetSchedule returns one schedule by id, or ErrNotFound.
func (s *Store) GetSchedule(ctx context.Context, id string) (Schedule, error) {
	out, err := scanSchedule(s.pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM schedules WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Schedule{}, ErrNotFound
		}
		return Schedule{}, err
	}
	return out, nil
}

// ListSchedules returns all schedules ordered by name.
func (s *Store) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduleCols+` FROM schedules ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Schedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// UpdateSchedule updates a schedule's mutable fields and returns the fresh row.
// NextRunAt is recomputed by the caller from the (possibly changed) cron/enabled.
func (s *Store) UpdateSchedule(ctx context.Context, id string, in Schedule) (Schedule, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE schedules
		 SET name = $2, target_id = $3, template_set_id = $4, cron = $5, enabled = $6,
		     next_run_at = $7, updated_at = now()
		 WHERE id = $1
		 RETURNING `+scheduleCols,
		id, in.Name, in.TargetID, nullStr(in.TemplateSetID), in.Cron, in.Enabled, in.NextRunAt,
	)
	out, err := scanSchedule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Schedule{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return Schedule{}, ErrConflict
		}
		if isForeignKeyViolation(err) {
			return Schedule{}, ErrInvalidRef
		}
		return Schedule{}, fmt.Errorf("update schedule: %w", err)
	}
	return out, nil
}

// DeleteSchedule removes a schedule, or returns ErrNotFound.
func (s *Store) DeleteSchedule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM schedules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DueSchedules returns enabled schedules whose next_run_at has arrived (<= now).
// A NULL next_run_at is treated as not due — the backend always sets it when a
// schedule is enabled, so NULL means "disabled or never scheduled."
func (s *Store) DueSchedules(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scheduleCols+`
		 FROM schedules
		 WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1
		 ORDER BY next_run_at`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Schedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// RecordScheduleRun advances a schedule after the ticker dispatches it: it stamps
// last_run_at/last_scan_id and sets the next fire time (computed by the backend).
func (s *Store) RecordScheduleRun(ctx context.Context, id, scanID string, ranAt, nextRunAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE schedules SET last_run_at = $2, last_scan_id = $3, next_run_at = $4, updated_at = now()
		 WHERE id = $1`,
		id, ranAt, nullStr(scanID), nextRunAt,
	)
	return err
}
