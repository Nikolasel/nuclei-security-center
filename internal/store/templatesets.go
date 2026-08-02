package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TemplateSetMode controls how a template set resolves its templates.
type TemplateSetMode string

const (
	TemplateSetModeExact   TemplateSetMode = "exact"
	TemplateSetModeAll     TemplateSetMode = "all"
	TemplateSetModeExclude TemplateSetMode = "exclude"
)

func normalizeTemplateSetMode(mode TemplateSetMode) (TemplateSetMode, error) {
	if mode == "" {
		return TemplateSetModeExact, nil
	}
	switch mode {
	case TemplateSetModeExact, TemplateSetModeAll, TemplateSetModeExclude:
		return mode, nil
	default:
		return "", ErrInvalidTemplateSetMode
	}
}

// TemplateSet selects which Nuclei templates a scan runs. Exact sets are
// driven by template_set_members; all sets resolve to every active catalog
// template; exclude sets resolve to every active template except their stored
// exclusions.
type TemplateSet struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Mode                TemplateSetMode `json:"mode"`
	MemberCount         int             `json:"member_count"`
	ExclusionCount      int             `json:"exclusion_count"`
	ExcludedTemplateIDs []string        `json:"excluded_template_ids,omitempty"`
	CreatedBy           string          `json:"created_by,omitempty"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

// tmplSetCols is the read projection shared by Get/List/Update. member_count is
// the effective selected count: stored exact membership for exact sets, or
// active catalog rows minus exclusions for catalog-derived sets.
const tmplSetCols = `id, name, mode,
	CASE WHEN mode IN ('all', 'exclude')
	     THEN (SELECT count(*) FROM templates
	            WHERE availability = 'active'
	              AND (template_sets.mode = 'all' OR NOT EXISTS (
	                  SELECT 1 FROM template_set_exclusions e
	                   WHERE e.template_set_id = template_sets.id
	                     AND e.template_id = templates.id
	              )))
	     ELSE (SELECT count(*) FROM template_set_members m WHERE m.template_set_id = template_sets.id)
	END,
	(SELECT count(*) FROM template_set_exclusions e WHERE e.template_set_id = template_sets.id),
	created_by, created_at, updated_at`

// CreateTemplateSet inserts a template set and returns it populated.
func (s *Store) CreateTemplateSet(ctx context.Context, in TemplateSet) (TemplateSet, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TemplateSet{}, fmt.Errorf("begin create template set: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	mode, err := normalizeTemplateSetMode(in.Mode)
	if err != nil {
		return TemplateSet{}, err
	}
	if mode != TemplateSetModeExclude && len(in.ExcludedTemplateIDs) > 0 {
		return TemplateSet{}, ErrTemplateSetExclusionsUnsupported
	}
	in.Mode = mode
	in.ID = types.NewID()
	if _, err := tx.Exec(ctx,
		`INSERT INTO template_sets (id, name, mode, created_by)
		 VALUES ($1, $2, $3, $4)`,
		in.ID, in.Name, in.Mode, nullStr(in.CreatedBy),
	); err != nil {
		if isUniqueViolation(err) {
			return TemplateSet{}, ErrConflict
		}
		return TemplateSet{}, fmt.Errorf("insert template set: %w", err)
	}
	if in.Mode == TemplateSetModeExclude && len(in.ExcludedTemplateIDs) > 0 {
		if err := insertTemplateSetExclusions(ctx, tx, in.ID, in.ExcludedTemplateIDs, in.CreatedBy); err != nil {
			return TemplateSet{}, fmt.Errorf("insert template set exclusions: %w", err)
		}
	}
	t, err := scanTemplateSet(tx.QueryRow(ctx,
		`SELECT `+tmplSetCols+` FROM template_sets WHERE id = $1`, in.ID))
	if err != nil {
		return TemplateSet{}, fmt.Errorf("insert template set: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return TemplateSet{}, fmt.Errorf("commit create template set: %w", err)
	}
	return t, nil
}

// GetTemplateSet returns one template set by id, or ErrNotFound.
func (s *Store) GetTemplateSet(ctx context.Context, id string) (TemplateSet, error) {
	return scanTemplateSet(s.pool.QueryRow(ctx,
		`SELECT `+tmplSetCols+` FROM template_sets WHERE id = $1`, id))
}

// ListTemplateSets returns all template sets ordered by name.
func (s *Store) ListTemplateSets(ctx context.Context) ([]TemplateSet, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+tmplSetCols+` FROM template_sets ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TemplateSet
	for rows.Next() {
		t, err := scanTemplateSet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpdateTemplateSet updates mutable fields and returns the fresh row.
func (s *Store) UpdateTemplateSet(ctx context.Context, id string, in TemplateSet) (TemplateSet, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TemplateSet{}, fmt.Errorf("begin update template set: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT true FROM template_sets WHERE id = $1 FOR UPDATE`, id,
	).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return TemplateSet{}, ErrNotFound
	} else if err != nil {
		return TemplateSet{}, err
	}
	mode, err := normalizeTemplateSetMode(in.Mode)
	if err != nil {
		return TemplateSet{}, err
	}
	if mode != TemplateSetModeExclude && len(in.ExcludedTemplateIDs) > 0 {
		return TemplateSet{}, ErrTemplateSetExclusionsUnsupported
	}
	if _, err := tx.Exec(ctx,
		`UPDATE template_sets
		 SET name = $2, mode = $3, updated_at = now()
		 WHERE id = $1`,
		id, in.Name, mode); err != nil {
		if isUniqueViolation(err) {
			return TemplateSet{}, ErrConflict
		}
		return TemplateSet{}, err
	}
	if mode != TemplateSetModeExact {
		if _, err := tx.Exec(ctx,
			`DELETE FROM template_set_members WHERE template_set_id = $1`, id); err != nil {
			return TemplateSet{}, fmt.Errorf("clear non-exact template set members: %w", err)
		}
	}
	if mode != TemplateSetModeExclude || in.ExcludedTemplateIDs != nil {
		if _, err := tx.Exec(ctx,
			`DELETE FROM template_set_exclusions WHERE template_set_id = $1`, id); err != nil {
			return TemplateSet{}, fmt.Errorf("clear template set exclusions: %w", err)
		}
		if mode == TemplateSetModeExclude && len(in.ExcludedTemplateIDs) > 0 {
			if err := insertTemplateSetExclusions(ctx, tx, id, in.ExcludedTemplateIDs, in.CreatedBy); err != nil {
				return TemplateSet{}, fmt.Errorf("insert template set exclusions: %w", err)
			}
		}
	}
	t, err := scanTemplateSet(tx.QueryRow(ctx,
		`SELECT `+tmplSetCols+` FROM template_sets WHERE id = $1`, id))
	if err != nil {
		return TemplateSet{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TemplateSet{}, fmt.Errorf("commit update template set: %w", err)
	}
	return t, nil
}

// DeleteTemplateSet removes a template set, or returns ErrNotFound.
func (s *Store) DeleteTemplateSet(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM template_sets WHERE id = $1`, id)
	if err != nil {
		if isForeignKeyViolation(err) {
			return ErrTemplateSetInUse
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanTemplateSet reads one row (projected with tmplSetCols) into a TemplateSet.
func scanTemplateSet(row pgx.Row) (TemplateSet, error) {
	var t TemplateSet
	var mode string
	var createdBy *string
	err := row.Scan(&t.ID, &t.Name, &mode,
		&t.MemberCount, &t.ExclusionCount, &createdBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TemplateSet{}, ErrNotFound
		}
		return TemplateSet{}, err
	}
	t.Mode = TemplateSetMode(mode)
	t.CreatedBy = deref(createdBy)
	return t, nil
}
