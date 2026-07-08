// Package store is the backend's Postgres access layer and system of record.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store wraps a pgx connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres and returns a Store. The caller must Close it.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Migrate applies any embedded migrations not yet recorded, in filename order.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, name,
		).Scan(&exists); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if exists {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := s.pool.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, name,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
	}
	return nil
}

// ScanLink optionally ties a scan to the stored config it came from. Empty
// fields mean an ad-hoc scan not linked to a target/template set.
type ScanLink struct {
	TargetID      string
	TemplateSetID string
}

// CreateScan inserts a new scan in the queued state and returns its id.
func (s *Store) CreateScan(ctx context.Context, spec types.ScanSpec, link ScanLink) (string, error) {
	id := types.NewID()
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("marshal spec: %w", err)
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO scans (id, state, spec, target_id, template_set_id)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, types.ScanQueued, specJSON, nullStr(link.TargetID), nullStr(link.TemplateSetID),
	)
	if err != nil {
		return "", fmt.Errorf("insert scan: %w", err)
	}
	return id, nil
}

// MarkRunning records the node's scan id and moves the scan to running.
func (s *Store) MarkRunning(ctx context.Context, scanID, nodeScanID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET state = $1, node_scan_id = $2, started_at = now() WHERE id = $3`,
		types.ScanRunning, nodeScanID, scanID,
	)
	return err
}

// MarkFailed records a terminal failure with its reason.
func (s *Store) MarkFailed(ctx context.Context, scanID, reason string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET state = $1, error = $2, finished_at = now() WHERE id = $3`,
		types.ScanFailed, reason, scanID,
	)
	return err
}

// MarkComplete records successful completion and the versions that ran.
func (s *Store) MarkComplete(ctx context.Context, scanID, nucleiVersion, templatesCommit string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET state = $1, nuclei_version = $2, templates_commit = $3, finished_at = now() WHERE id = $4`,
		types.ScanComplete, nucleiVersion, templatesCommit, scanID,
	)
	return err
}

// InsertFinding stores one parsed finding plus its verbatim raw JSON line.
func (s *Store) InsertFinding(ctx context.Context, scanID string, f types.NucleiFinding, raw []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO findings (scan_id, template_id, name, severity, host, matched_at, type, raw)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		scanID, f.TemplateID, f.Info.Name, f.Info.Severity, f.Host, f.MatchedAt, f.Type, raw,
	)
	return err
}

// ScanRow is a scan as returned to API callers.
type ScanRow struct {
	ID              string     `json:"id"`
	State           string     `json:"state"`
	NucleiVersion   string     `json:"nuclei_version,omitempty"`
	TemplatesCommit string     `json:"templates_commit,omitempty"`
	Error           string     `json:"error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
}

// GetScan returns one scan by id.
func (s *Store) GetScan(ctx context.Context, id string) (ScanRow, error) {
	var r ScanRow
	var nucleiVersion, templatesCommit, errStr *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, state, nuclei_version, templates_commit, error, created_at, finished_at
		 FROM scans WHERE id = $1`, id,
	).Scan(&r.ID, &r.State, &nucleiVersion, &templatesCommit, &errStr, &r.CreatedAt, &r.FinishedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return ScanRow{}, ErrNotFound
		}
		return ScanRow{}, err
	}
	r.NucleiVersion = deref(nucleiVersion)
	r.TemplatesCommit = deref(templatesCommit)
	r.Error = deref(errStr)
	return r, nil
}

// ListScans returns recent scans, newest first.
func (s *Store) ListScans(ctx context.Context, limit int) ([]ScanRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, state, nuclei_version, templates_commit, error, created_at, finished_at
		 FROM scans ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanRow
	for rows.Next() {
		var r ScanRow
		var nucleiVersion, templatesCommit, errStr *string
		if err := rows.Scan(&r.ID, &r.State, &nucleiVersion, &templatesCommit, &errStr,
			&r.CreatedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		r.NucleiVersion = deref(nucleiVersion)
		r.TemplatesCommit = deref(templatesCommit)
		r.Error = deref(errStr)
		out = append(out, r)
	}
	return out, rows.Err()
}

// FindingRow is a finding as returned to API callers.
type FindingRow struct {
	ID         int64     `json:"id"`
	ScanID     string    `json:"scan_id"`
	TemplateID string    `json:"template_id"`
	Name       string    `json:"name"`
	Severity   string    `json:"severity"`
	Host       string    `json:"host"`
	MatchedAt  string    `json:"matched_at"`
	Type       string    `json:"type"`
	CreatedAt  time.Time `json:"created_at"`
}

// ListFindings returns findings, most recent first, optionally filtered by scan.
func (s *Store) ListFindings(ctx context.Context, scanID string, limit int) ([]FindingRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows pgx.Rows
	var err error
	if scanID != "" {
		rows, err = s.pool.Query(ctx,
			`SELECT id, scan_id, template_id, name, severity, host, matched_at, type, created_at
			 FROM findings WHERE scan_id = $1 ORDER BY id DESC LIMIT $2`, scanID, limit)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT id, scan_id, template_id, name, severity, host, matched_at, type, created_at
			 FROM findings ORDER BY id DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		if err := rows.Scan(&f.ID, &f.ScanID, &f.TemplateID, &f.Name, &f.Severity,
			&f.Host, &f.MatchedAt, &f.Type, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
