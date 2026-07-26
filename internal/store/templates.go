package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// TemplateFilter narrows a catalog listing. Every field is optional; an empty
// field does not constrain. It compiles to a fully parameterized WHERE clause —
// user values never touch the SQL text.
type TemplateFilter struct {
	Source             string   // "upstream" | "custom" | "" (any)
	Severities         []string // any-of, case-insensitive
	Tags               []string // any-of (array overlap on tags[])
	Query              string   // case-insensitive substring over id/name/description
	Sort               string   // "name" (default) | "inserted" (newest first)
	IncludeUnavailable bool     // false (default) ⇒ only availability='active'
}

// tmplListCols are the catalog columns returned by list/get, excluding the
// (potentially large) yaml body — the list view never needs it, and callers that
// do (the editor) fetch a single row via GetTemplate.
const tmplListCols = `id, source, path, content_sha256, name, author, severity,
	description, tags, upstream_ref, revision, availability, created_by, created_at, updated_at`

// ListTemplates returns a filtered, paginated page of the catalog plus the total
// matching count (for the UI's pager). yaml is omitted from list rows.
func (s *Store) ListTemplates(ctx context.Context, f TemplateFilter, limit, offset int) ([]Template, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	where, args := templateFilterWhere(f)

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM templates "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count templates: %w", err)
	}

	args = append(args, limit)
	limitPH := fmt.Sprintf("$%d", len(args))
	args = append(args, offset)
	offsetPH := fmt.Sprintf("$%d", len(args))
	rows, err := s.pool.Query(ctx,
		"SELECT "+tmplListCols+" FROM templates "+where+
			" ORDER BY "+templateSortOrder(f.Sort)+" LIMIT "+limitPH+" OFFSET "+offsetPH, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list templates: %w", err)
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		t, err := scanTemplateList(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// ListTemplateIDs returns every id matching the same catalog filter used by the
// paginated list. The set editor uses this lightweight projection for "select
// all matching" without downloading every template row.
func (s *Store) ListTemplateIDs(ctx context.Context, f TemplateFilter) ([]string, error) {
	where, args := templateFilterWhere(f)
	rows, err := s.pool.Query(ctx,
		"SELECT id FROM templates "+where+" ORDER BY "+templateSortOrder(f.Sort), args...)
	if err != nil {
		return nil, fmt.Errorf("list template ids: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func templateFilterWhere(f TemplateFilter) (string, []any) {
	var conds []string
	var args []any
	push := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if !f.IncludeUnavailable {
		conds = append(conds, "availability = 'active'")
	}
	if f.Source != "" {
		conds = append(conds, "source = "+push(f.Source))
	}
	if len(f.Severities) > 0 {
		lowered := make([]string, len(f.Severities))
		for i, sev := range f.Severities {
			lowered[i] = strings.ToLower(sev)
		}
		conds = append(conds, "lower(severity) = ANY("+push(lowered)+")")
	}
	if len(f.Tags) > 0 {
		conds = append(conds, "tags && "+push(f.Tags))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		p := push("%" + q + "%")
		conds = append(conds, "(id ILIKE "+p+" OR name ILIKE "+p+" OR description ILIKE "+p+")")
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func templateSortOrder(sortBy string) string {
	if sortBy == "inserted" {
		return "created_at DESC, lower(name), id"
	}
	return "lower(name), id"
}

// GetTemplate returns one template by id including its yaml body, or ErrNotFound.
func (s *Store) GetTemplate(ctx context.Context, id string) (Template, error) {
	var t Template
	var upstreamRef, createdBy *string
	err := s.pool.QueryRow(ctx,
		"SELECT "+tmplListCols+", yaml FROM templates WHERE id = $1", id,
	).Scan(&t.ID, &t.Source, &t.Path, &t.ContentSHA256, &t.Name, &t.Author, &t.Severity,
		&t.Description, &t.Tags, &upstreamRef, &t.Revision, &t.Availability, &createdBy,
		&t.CreatedAt, &t.UpdatedAt, &t.YAML)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Template{}, ErrNotFound
		}
		return Template{}, fmt.Errorf("get template: %w", err)
	}
	t.UpstreamRef = deref(upstreamRef)
	t.CreatedBy = deref(createdBy)
	return t, nil
}

// GetTemplatesByIDs returns the requested catalog rows including verbatim YAML,
// ordered by id. Missing ids are simply absent; the export handler compares the
// result with its normalized request so it can report all missing ids together.
func (s *Store) GetTemplatesByIDs(ctx context.Context, ids []string) ([]Template, error) {
	if len(ids) == 0 {
		return []Template{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+tmplListCols+`, yaml FROM templates WHERE id = ANY($1) ORDER BY id`, ids)
	if err != nil {
		return nil, fmt.Errorf("get templates by ids: %w", err)
	}
	defer rows.Close()
	out := make([]Template, 0, len(ids))
	for rows.Next() {
		t, err := scanTemplate(rows, true)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TemplateSources returns every catalog id and its owner ("upstream" or
// "custom"). Import uses one snapshot to resolve conflicts and validate a set's
// member ids without issuing one query per archive entry.
func (s *Store) TemplateSources(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, source FROM templates`)
	if err != nil {
		return nil, fmt.Errorf("list template identities: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var id, source string
		if err := rows.Scan(&id, &source); err != nil {
			return nil, err
		}
		out[id] = source
	}
	return out, rows.Err()
}

// scanTemplateList scans a row selected with tmplListCols (no yaml).
func scanTemplateList(rows pgx.Rows) (Template, error) {
	return scanTemplate(rows, false)
}

func scanTemplate(row pgx.Row, withYAML bool) (Template, error) {
	var t Template
	var upstreamRef, createdBy *string
	dest := []any{
		&t.ID, &t.Source, &t.Path, &t.ContentSHA256, &t.Name, &t.Author,
		&t.Severity, &t.Description, &t.Tags, &upstreamRef, &t.Revision,
		&t.Availability, &createdBy, &t.CreatedAt, &t.UpdatedAt,
	}
	if withYAML {
		dest = append(dest, &t.YAML)
	}
	if err := row.Scan(dest...); err != nil {
		return Template{}, err
	}
	t.UpstreamRef = deref(upstreamRef)
	t.CreatedBy = deref(createdBy)
	return t, nil
}

// CreateCustomTemplate inserts a user-authored template (source='custom'). The
// caller supplies the parsed metadata + verbatim YAML. A duplicate id — whether
// an existing custom OR upstream row (the PK is the Nuclei id) — is ErrConflict,
// which is how a custom template is prevented from shadowing an upstream one.
func (s *Store) CreateCustomTemplate(ctx context.Context, t Template) (Template, error) {
	t.Source = "custom"
	t.Availability = "active"
	t.Revision = 1
	err := s.pool.QueryRow(ctx,
		`INSERT INTO templates (id, source, path, yaml, content_sha256, name, author, severity,
		   description, tags, revision, availability, created_by)
		 VALUES ($1, 'custom', $2, $3, $4, $5, $6, $7, $8, $9, 1, 'active', $10)
		 RETURNING created_at, updated_at`,
		t.ID, t.Path, t.YAML, t.ContentSHA256, t.Name, t.Author, t.Severity,
		t.Description, orEmpty(t.Tags), nullStr(t.CreatedBy),
	).Scan(&t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Template{}, ErrConflict
		}
		return Template{}, fmt.Errorf("insert custom template: %w", err)
	}
	return t, nil
}

// UpdateCustomTemplate replaces a custom template's body and bumps its revision.
// It refuses to touch an upstream row (ErrTemplateReadOnly) and reports
// ErrNotFound for a missing id. The caller guarantees the parsed id equals the
// target id, so the primary key never changes here.
func (s *Store) UpdateCustomTemplate(ctx context.Context, id string, t Template) (Template, error) {
	if err := s.assertCustom(ctx, id); err != nil {
		return Template{}, err
	}
	t.ID = id
	t.Source = "custom"
	t.Availability = "active"
	var createdBy *string
	err := s.pool.QueryRow(ctx,
		`UPDATE templates SET path = $2, yaml = $3, content_sha256 = $4, name = $5, author = $6,
		   severity = $7, description = $8, tags = $9, revision = revision + 1, updated_at = now()
		 WHERE id = $1 AND source = 'custom'
		 RETURNING revision, created_by, created_at, updated_at`,
		id, t.Path, t.YAML, t.ContentSHA256, t.Name, t.Author, t.Severity, t.Description, orEmpty(t.Tags),
	).Scan(&t.Revision, &createdBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Template{}, ErrNotFound
		}
		return Template{}, fmt.Errorf("update custom template: %w", err)
	}
	t.CreatedBy = deref(createdBy)
	return t, nil
}

// DeleteCustomTemplate removes a custom template. Upstream rows are read-only
// (ErrTemplateReadOnly); a missing id is ErrNotFound.
func (s *Store) DeleteCustomTemplate(ctx context.Context, id string) error {
	if err := s.assertCustom(ctx, id); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM templates WHERE id = $1 AND source = 'custom'`, id)
	if err != nil {
		return fmt.Errorf("delete custom template: %w", err)
	}
	return nil
}

// assertCustom returns ErrNotFound if the id is unknown, or ErrTemplateReadOnly
// if it exists but is upstream — so the mutating handlers can reject before the
// write and map a clean status code.
func (s *Store) assertCustom(ctx context.Context, id string) error {
	var source string
	err := s.pool.QueryRow(ctx, `SELECT source FROM templates WHERE id = $1`, id).Scan(&source)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup template: %w", err)
	}
	if source != "custom" {
		return ErrTemplateReadOnly
	}
	return nil
}

// ListTemplateSyncRuns returns the most recent sync-run rows (newest first) for
// the Sync view — time-since-last-sync, counts, and any error.
func (s *Store) ListTemplateSyncRuns(ctx context.Context, limit int) ([]TemplateSyncRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, started_at, finished_at, status, ref_before, ref_after,
		   added, removed, updated, skipped, error
		 FROM template_sync_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list template sync runs: %w", err)
	}
	defer rows.Close()
	var out []TemplateSyncRun
	for rows.Next() {
		var r TemplateSyncRun
		var refBefore, refAfter, errStr *string
		if err := rows.Scan(&r.ID, &r.StartedAt, &r.FinishedAt, &r.Status, &refBefore, &refAfter,
			&r.Added, &r.Removed, &r.Updated, &r.Skipped, &errStr); err != nil {
			return nil, err
		}
		r.RefBefore, r.RefAfter, r.Error = deref(refBefore), deref(refAfter), deref(errStr)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveTemplateBundleEntries returns the id/path/sha256 of every active template
// (no YAML) — enough to compute the catalog's canonical bundle digest cheaply, so
// the distributor can decide whether a node is already current before building
// the (heavier) full bundle. Ordered by id for a stable manifest.
func (s *Store) ActiveTemplateBundleEntries(ctx context.Context) ([]types.TemplateBundleEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, path, content_sha256 FROM templates WHERE availability = 'active' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list template bundle entries: %w", err)
	}
	defer rows.Close()
	var out []types.TemplateBundleEntry
	for rows.Next() {
		var e types.TemplateBundleEntry
		if err := rows.Scan(&e.ID, &e.Path, &e.SHA256); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TemplatesUpdatedAfter reports whether any selected active template changed
// after ts. The orchestrator combines this DB-driven signal with the node's
// reported bundle digest before dispatch, so a set changed since the last push
// is topped up even if a health snapshot is stale.
func (s *Store) TemplatesUpdatedAfter(ctx context.Context, ids []string, ts time.Time) (bool, error) {
	if len(ids) == 0 {
		return false, nil
	}
	var updated bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM templates
			 WHERE availability = 'active' AND id = ANY($1) AND updated_at > $2
		)`, ids, ts).Scan(&updated)
	if err != nil {
		return false, fmt.Errorf("check selected template freshness: %w", err)
	}
	return updated, nil
}

// ListActiveTemplateBodies returns every active template with its verbatim YAML,
// for building the full catalog bundle pushed to a node (#85).
func (s *Store) ListActiveTemplateBodies(ctx context.Context) ([]Template, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, path, yaml, content_sha256 FROM templates WHERE availability = 'active' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list active template bodies: %w", err)
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		if err := rows.Scan(&t.ID, &t.Path, &t.YAML, &t.ContentSHA256); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
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
