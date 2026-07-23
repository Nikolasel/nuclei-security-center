package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Template is one Nuclei template known to NSC. YAML is intentionally the
// only complete representation: all other content fields are extracted solely
// for filtering and display, so exporting or dispatching never has to rebuild
// YAML from a lossy intermediary representation.
type Template struct {
	ID            string    `json:"id"`
	Source        string    `json:"source"`
	Path          string    `json:"path"`
	YAML          string    `json:"-"`
	ContentSHA256 string    `json:"content_sha256"`
	Name          string    `json:"name"`
	Author        string    `json:"author"`
	Severity      string    `json:"severity"`
	Description   string    `json:"description"`
	Tags          []string  `json:"tags"`
	UpstreamRef   string    `json:"upstream_ref,omitempty"`
	Revision      int       `json:"revision"`
	Availability  string    `json:"availability"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TemplateSyncRun is an auditable outcome of one upstream catalog refresh.
type TemplateSyncRun struct {
	ID         string     `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
	RefBefore  string     `json:"ref_before,omitempty"`
	RefAfter   string     `json:"ref_after,omitempty"`
	Added      int        `json:"added"`
	Removed    int        `json:"removed"`
	Updated    int        `json:"updated"`
	Skipped    int        `json:"skipped"`
	Error      string     `json:"error,omitempty"`
}

// TemplateSyncStats summarizes the catalog changes made by an upstream sync.
type TemplateSyncStats struct {
	Added   int
	Removed int
	Updated int
	Skipped int
}

// StartTemplateSync records a sync attempt before network work begins, so a
// failed clone/fetch is visible just like a failed database update.
func (s *Store) StartTemplateSync(ctx context.Context) (TemplateSyncRun, error) {
	run := TemplateSyncRun{ID: types.NewID(), StartedAt: time.Now().UTC(), Status: "running"}
	var before *string
	err := s.pool.QueryRow(ctx,
		`SELECT ref_after FROM template_sync_runs WHERE status = 'success' ORDER BY finished_at DESC LIMIT 1`).Scan(&before)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return TemplateSyncRun{}, fmt.Errorf("read previous template sync: %w", err)
	}
	run.RefBefore = deref(before)
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO template_sync_runs (id, started_at, status, ref_before) VALUES ($1, $2, $3, $4)`,
		run.ID, run.StartedAt, run.Status, nullStr(run.RefBefore)); err != nil {
		return TemplateSyncRun{}, fmt.Errorf("start template sync: %w", err)
	}
	return run, nil
}

// ApplyUpstreamTemplates replaces the active upstream catalog in one
// transaction. Templates absent from a successful source snapshot are retained
// as unavailable instead of deleted, so a curated set can never silently lose a
// member when upstream removes a file.
func (s *Store) ApplyUpstreamTemplates(ctx context.Context, runID, ref string, in []Template, skipped int) (TemplateSyncStats, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TemplateSyncStats{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existingRows, err := tx.Query(ctx, `SELECT id, content_sha256, availability FROM templates WHERE source = 'upstream'`)
	if err != nil {
		return TemplateSyncStats{}, fmt.Errorf("list upstream templates: %w", err)
	}
	existing := make(map[string]struct {
		hash         string
		availability string
	})
	for existingRows.Next() {
		var id, hash, availability string
		if err := existingRows.Scan(&id, &hash, &availability); err != nil {
			existingRows.Close()
			return TemplateSyncStats{}, err
		}
		existing[id] = struct{ hash, availability string }{hash, availability}
	}
	if err := existingRows.Err(); err != nil {
		existingRows.Close()
		return TemplateSyncStats{}, err
	}
	existingRows.Close()

	// Nuclei's id is its runtime identity, so a custom template may not shadow
	// an upstream one (or vice versa). Failing the sync is safer than making a
	// set resolve to different YAML without the operator noticing.
	incomingIDs := make([]string, 0, len(in))
	for _, t := range in {
		incomingIDs = append(incomingIDs, t.ID)
	}
	var customID string
	err = tx.QueryRow(ctx, `SELECT id FROM templates WHERE source = 'custom' AND id = ANY($1) LIMIT 1`, incomingIDs).Scan(&customID)
	if err == nil {
		return TemplateSyncStats{}, fmt.Errorf("upstream template id %q conflicts with a custom template", customID)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return TemplateSyncStats{}, fmt.Errorf("check custom template conflicts: %w", err)
	}

	ids := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	stats := TemplateSyncStats{Skipped: skipped}
	for _, t := range in {
		if _, ok := seen[t.ID]; ok {
			return TemplateSyncStats{}, fmt.Errorf("duplicate template id %q in upstream catalog", t.ID)
		}
		seen[t.ID] = struct{}{}
		ids = append(ids, t.ID)
		old, found := existing[t.ID]
		if !found {
			stats.Added++
		} else if old.hash != t.ContentSHA256 || old.availability != "active" {
			stats.Updated++
		}
		// The WHERE guard re-asserts the custom/upstream shadow check at write
		// time: if a custom row with this id were inserted after the pre-check
		// above (a tiny race), the DO UPDATE matches zero rows and this upstream
		// template is silently skipped rather than overwriting the custom one —
		// the safe direction, but a silent no-op worth calling out.
		_, err := tx.Exec(ctx,
			`INSERT INTO templates (id, source, path, yaml, content_sha256, name, author, severity, description, tags, upstream_ref, availability)
			 VALUES ($1, 'upstream', $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')
			 ON CONFLICT (id) DO UPDATE SET
			   path = EXCLUDED.path, yaml = EXCLUDED.yaml, content_sha256 = EXCLUDED.content_sha256,
			   name = EXCLUDED.name, author = EXCLUDED.author, severity = EXCLUDED.severity,
			   description = EXCLUDED.description, tags = EXCLUDED.tags, upstream_ref = EXCLUDED.upstream_ref,
			   availability = 'active', updated_at = now()
			 WHERE templates.source = 'upstream'`,
			t.ID, t.Path, t.YAML, t.ContentSHA256, t.Name, t.Author, t.Severity, t.Description, orEmpty(t.Tags), ref)
		if err != nil {
			return TemplateSyncStats{}, fmt.Errorf("upsert template %q: %w", t.ID, err)
		}
	}

	// Tombstone (retain, don't delete) templates upstream removed, AND free their
	// path. UNIQUE (source, path) would otherwise be poisoned forever: nuclei
	// renames files and reassigns ids regularly, so a later, different id landing
	// on a removed template's path would collide with the tombstone and fail every
	// subsequent sync. Reparking the path under a per-id 'tombstone:' sentinel
	// keeps it unique (id is unique per source) while leaving the real path open;
	// if the id ever returns upstream the ON CONFLICT (id) upsert restores it. The
	// deferred constraint (migration 0018) lets these renames overlap within the
	// transaction. An empty catalog is a valid snapshot only when the source was
	// genuinely empty; the caller fails parse/walk errors before reaching here.
	removed, err := tx.Exec(ctx,
		`UPDATE templates SET availability = 'unavailable', path = 'tombstone:' || id, updated_at = now()
		 WHERE source = 'upstream' AND availability = 'active' AND NOT (id = ANY($1))`, ids)
	if err != nil {
		return TemplateSyncStats{}, fmt.Errorf("tombstone removed upstream templates: %w", err)
	}
	stats.Removed = int(removed.RowsAffected())
	if _, err := tx.Exec(ctx,
		`UPDATE template_sync_runs SET finished_at = now(), status = 'success', ref_after = $2,
		 added = $3, removed = $4, updated = $5, skipped = $6, error = NULL WHERE id = $1`,
		runID, ref, stats.Added, stats.Removed, stats.Updated, stats.Skipped); err != nil {
		return TemplateSyncStats{}, fmt.Errorf("complete template sync: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return TemplateSyncStats{}, err
	}
	return stats, nil
}

// ReapStaleTemplateSyncRuns marks 'running' rows that have outlived the sync
// timeout as failed. A backend crash mid-sync would otherwise leave a row stuck
// at 'running' forever; this is called before each tick so the runs history
// reflects reality. It uses started_at (finished_at is NULL while running).
func (s *Store) ReapStaleTemplateSyncRuns(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan)
	tag, err := s.pool.Exec(ctx,
		`UPDATE template_sync_runs SET finished_at = now(), status = 'failed',
		 error = 'reaped: backend restarted or timed out mid-sync'
		 WHERE status = 'running' AND started_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("reap stale template sync runs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// FailTemplateSync finishes an attempt that failed before its catalog changes
// could be applied.
func (s *Store) FailTemplateSync(ctx context.Context, runID string, cause error) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE template_sync_runs SET finished_at = now(), status = 'failed', error = $2 WHERE id = $1`,
		runID, cause.Error())
	if err != nil {
		return fmt.Errorf("record failed template sync: %w", err)
	}
	return nil
}
