package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// setExists returns ErrNotFound if the template set id is unknown, so member
// operations report a clean 404 on the set itself (distinct from a bad member
// id, which surfaces as ErrInvalidRef via the foreign key).
func (s *Store) setExists(ctx context.Context, setID string) error {
	var one int
	err := s.pool.QueryRow(ctx, `SELECT 1 FROM template_sets WHERE id = $1`, setID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ListTemplateSetMembers returns the catalog rows for a set's members, ordered
// like the catalog list (yaml omitted). ErrNotFound if the set is unknown.
func (s *Store) ListTemplateSetMembers(ctx context.Context, setID string) ([]Template, error) {
	if err := s.setExists(ctx, setID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+tmplListCols+` FROM templates
		 JOIN template_set_members m ON m.template_id = templates.id
		 WHERE m.template_set_id = $1
		 ORDER BY lower(name), id`, setID)
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
	if err := s.setExists(ctx, setID); err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM template_set_members WHERE template_set_id = $1`, setID); err != nil {
		return 0, fmt.Errorf("clear template set members: %w", err)
	}
	seen := make(map[string]struct{}, len(ids))
	count := 0
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if _, err := tx.Exec(ctx,
			`INSERT INTO template_set_members (template_set_id, template_id, added_by)
			 VALUES ($1, $2, $3)`, setID, id, nullStr(addedBy)); err != nil {
			if isForeignKeyViolation(err) {
				return 0, ErrInvalidRef
			}
			return 0, fmt.Errorf("insert template set member: %w", err)
		}
		count++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

// AddTemplateSetMembers adds ids to a set, ignoring ones already present
// (idempotent). Unknown template id ⇒ ErrInvalidRef; unknown set ⇒ ErrNotFound.
func (s *Store) AddTemplateSetMembers(ctx context.Context, setID string, ids []string, addedBy string) error {
	if err := s.setExists(ctx, setID); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO template_set_members (template_set_id, template_id, added_by)
			 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, setID, id, nullStr(addedBy)); err != nil {
			if isForeignKeyViolation(err) {
				return ErrInvalidRef
			}
			return fmt.Errorf("add template set member: %w", err)
		}
	}
	return nil
}

// RemoveTemplateSetMember removes one template from a set. ErrNotFound if the
// set is unknown or the template is not a member.
func (s *Store) RemoveTemplateSetMember(ctx context.Context, setID, templateID string) error {
	if err := s.setExists(ctx, setID); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM template_set_members WHERE template_set_id = $1 AND template_id = $2`, setID, templateID)
	if err != nil {
		return fmt.Errorf("remove template set member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
