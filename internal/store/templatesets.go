package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TemplateSet selects which Nuclei templates a scan runs. Exact sets are driven
// by template_set_members; DynamicAll resolves to every active catalog template
// at read and dispatch time.
type TemplateSet struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DynamicAll  bool      `json:"dynamic_all"`
	MemberCount int       `json:"member_count"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// tmplSetCols is the read projection shared by Get/List/Update. member_count is
// live for both exact membership and the dynamic active-catalog mode.
const tmplSetCols = `id, name, dynamic_all,
	CASE WHEN dynamic_all
	     THEN (SELECT count(*) FROM templates WHERE availability = 'active')
	     ELSE (SELECT count(*) FROM template_set_members m WHERE m.template_set_id = template_sets.id)
	END,
	created_by, created_at, updated_at`

// CreateTemplateSet inserts a template set and returns it populated.
func (s *Store) CreateTemplateSet(ctx context.Context, in TemplateSet) (TemplateSet, error) {
	in.ID = types.NewID()
	t, err := scanTemplateSet(s.pool.QueryRow(ctx,
		`INSERT INTO template_sets (id, name, dynamic_all, created_by)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+tmplSetCols,
		in.ID, in.Name, in.DynamicAll, nullStr(in.CreatedBy),
	))
	if err != nil {
		if isUniqueViolation(err) {
			return TemplateSet{}, ErrConflict
		}
		return TemplateSet{}, fmt.Errorf("insert template set: %w", err)
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
	t, err := scanTemplateSet(tx.QueryRow(ctx,
		`UPDATE template_sets
		 SET name = $2, dynamic_all = $3, updated_at = now()
		 WHERE id = $1
		 RETURNING `+tmplSetCols,
		id, in.Name, in.DynamicAll))
	if err != nil {
		if isUniqueViolation(err) {
			return TemplateSet{}, ErrConflict
		}
		return TemplateSet{}, err
	}
	if in.DynamicAll {
		if _, err := tx.Exec(ctx,
			`DELETE FROM template_set_members WHERE template_set_id = $1`, id); err != nil {
			return TemplateSet{}, fmt.Errorf("clear dynamic template set members: %w", err)
		}
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
	var createdBy *string
	err := row.Scan(&t.ID, &t.Name, &t.DynamicAll,
		&t.MemberCount, &createdBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TemplateSet{}, ErrNotFound
		}
		return TemplateSet{}, err
	}
	t.CreatedBy = deref(createdBy)
	return t, nil
}
