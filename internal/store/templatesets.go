package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TemplateSet selects which Nuclei templates a scan runs: an optional pinned
// git ref plus severity/tag/path filters. It maps to types.TemplateSelector.
type TemplateSet struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	GitRef     string    `json:"git_ref,omitempty"`
	Severities []string  `json:"severities"`
	Tags       []string  `json:"tags"`
	Paths      []string  `json:"paths"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Selector converts a stored TemplateSet into the wire selector sent to the node.
func (t TemplateSet) Selector() types.TemplateSelector {
	return types.TemplateSelector{
		GitRef:     t.GitRef,
		Severities: t.Severities,
		Tags:       t.Tags,
		Paths:      t.Paths,
	}
}

// CreateTemplateSet inserts a template set and returns it populated.
func (s *Store) CreateTemplateSet(ctx context.Context, in TemplateSet) (TemplateSet, error) {
	in.ID = types.NewID()
	in.Severities, in.Tags, in.Paths = orEmpty(in.Severities), orEmpty(in.Tags), orEmpty(in.Paths)
	err := s.pool.QueryRow(ctx,
		`INSERT INTO template_sets (id, name, git_ref, severities, tags, paths, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING created_at, updated_at`,
		in.ID, in.Name, nullStr(in.GitRef), in.Severities, in.Tags, in.Paths, nullStr(in.CreatedBy),
	).Scan(&in.CreatedAt, &in.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return TemplateSet{}, ErrConflict
		}
		return TemplateSet{}, fmt.Errorf("insert template set: %w", err)
	}
	return in, nil
}

// GetTemplateSet returns one template set by id, or ErrNotFound.
func (s *Store) GetTemplateSet(ctx context.Context, id string) (TemplateSet, error) {
	return scanTemplateSet(s.pool.QueryRow(ctx,
		`SELECT id, name, git_ref, severities, tags, paths, created_by, created_at, updated_at
		 FROM template_sets WHERE id = $1`, id))
}

// ListTemplateSets returns all template sets ordered by name.
func (s *Store) ListTemplateSets(ctx context.Context) ([]TemplateSet, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, git_ref, severities, tags, paths, created_by, created_at, updated_at
		 FROM template_sets ORDER BY lower(name)`)
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
	in.Severities, in.Tags, in.Paths = orEmpty(in.Severities), orEmpty(in.Tags), orEmpty(in.Paths)
	t, err := scanTemplateSet(s.pool.QueryRow(ctx,
		`UPDATE template_sets
		 SET name = $2, git_ref = $3, severities = $4, tags = $5, paths = $6, updated_at = now()
		 WHERE id = $1
		 RETURNING id, name, git_ref, severities, tags, paths, created_by, created_at, updated_at`,
		id, in.Name, nullStr(in.GitRef), in.Severities, in.Tags, in.Paths))
	if err != nil {
		if isUniqueViolation(err) {
			return TemplateSet{}, ErrConflict
		}
		return TemplateSet{}, err
	}
	return t, nil
}

// DeleteTemplateSet removes a template set, or returns ErrNotFound.
func (s *Store) DeleteTemplateSet(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM template_sets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanTemplateSet reads one row from a Query or QueryRow into a TemplateSet.
func scanTemplateSet(row pgx.Row) (TemplateSet, error) {
	var t TemplateSet
	var gitRef, createdBy *string
	err := row.Scan(&t.ID, &t.Name, &gitRef, &t.Severities, &t.Tags, &t.Paths,
		&createdBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TemplateSet{}, ErrNotFound
		}
		return TemplateSet{}, err
	}
	t.GitRef = deref(gitRef)
	t.CreatedBy = deref(createdBy)
	return t, nil
}
