package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// requireStaticTemplateSet locks the set row and rejects dynamic membership
// edits. A dynamic set always resolves from the active catalog.
func requireStaticTemplateSet(ctx context.Context, tx pgx.Tx, setID string) error {
	var dynamic bool
	err := tx.QueryRow(ctx,
		`SELECT dynamic_all FROM template_sets WHERE id = $1 FOR UPDATE`, setID,
	).Scan(&dynamic)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if dynamic {
		return ErrTemplateSetDynamic
	}
	return nil
}

// ListTemplateSetMembers returns the catalog rows for a set's members, ordered
// like the catalog list (yaml omitted). Dynamic sets resolve to every active
// template. ErrNotFound if the set is unknown.
func (s *Store) ListTemplateSetMembers(ctx context.Context, setID string) ([]Template, error) {
	var dynamic bool
	err := s.pool.QueryRow(ctx,
		`SELECT dynamic_all FROM template_sets WHERE id = $1`, setID,
	).Scan(&dynamic)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	query := `SELECT ` + tmplListCols + ` FROM templates
		JOIN template_set_members m ON m.template_id = templates.id
		WHERE m.template_set_id = $1
		ORDER BY lower(name), id`
	args := []any{setID}
	if dynamic {
		query = `SELECT ` + tmplListCols + ` FROM templates
			WHERE availability = 'active'
			ORDER BY lower(name), id`
		args = nil
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list template set members: %w", err)
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		t, err := scanTemplateList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ReplaceTemplateSetMembers sets a set's membership to exactly the given ids (the
// editor's save). It runs in one transaction: clear, then insert the deduped
// ids. An unknown template id is ErrInvalidRef (FK); an unknown set is
// ErrNotFound. Returns the resulting member count.
func (s *Store) ReplaceTemplateSetMembers(ctx context.Context, setID string, ids []string, addedBy string) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireStaticTemplateSet(ctx, tx, setID); err != nil {
		return 0, err
	}

	if _, err := tx.Exec(ctx, `DELETE FROM template_set_members WHERE template_set_id = $1`, setID); err != nil {
		return 0, fmt.Errorf("clear template set members: %w", err)
	}
	seen := make(map[string]struct{}, len(ids))
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) > 0 {
		if _, err := tx.Exec(ctx,
			`INSERT INTO template_set_members (template_set_id, template_id, added_by)
			 SELECT $1, template_id, $3
			 FROM unnest($2::text[]) AS selected(template_id)`,
			setID, unique, nullStr(addedBy)); err != nil {
			if isForeignKeyViolation(err) {
				return 0, ErrInvalidRef
			}
			return 0, fmt.Errorf("insert template set member: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(unique), nil
}

// AddTemplateSetMembers adds ids to a set, ignoring ones already present
// (idempotent). Unknown template id ⇒ ErrInvalidRef; unknown set ⇒ ErrNotFound.
func (s *Store) AddTemplateSetMembers(ctx context.Context, setID string, ids []string, addedBy string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin add template set members: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireStaticTemplateSet(ctx, tx, setID); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx,
			`INSERT INTO template_set_members (template_set_id, template_id, added_by)
			 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, setID, id, nullStr(addedBy)); err != nil {
			if isForeignKeyViolation(err) {
				return ErrInvalidRef
			}
			return fmt.Errorf("add template set member: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit add template set members: %w", err)
	}
	return nil
}

// RemoveTemplateSetMember removes one template from a set. ErrNotFound if the
// set is unknown or the template is not a member.
func (s *Store) RemoveTemplateSetMember(ctx context.Context, setID, templateID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin remove template set member: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireStaticTemplateSet(ctx, tx, setID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM template_set_members WHERE template_set_id = $1 AND template_id = $2`, setID, templateID)
	if err != nil {
		return fmt.Errorf("remove template set member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit remove template set member: %w", err)
	}
	return nil
}
