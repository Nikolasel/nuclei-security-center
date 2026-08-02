package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// requireExcludeTemplateSet locks the set row and permits exclusions only on
// the explicit exclude mode. Exact and all modes have no exclusion rows.
func requireExcludeTemplateSet(ctx context.Context, tx pgx.Tx, setID string) error {
	var mode TemplateSetMode
	err := tx.QueryRow(ctx,
		`SELECT mode FROM template_sets WHERE id = $1 FOR UPDATE`, setID,
	).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if mode != TemplateSetModeExclude {
		return ErrTemplateSetExclusionsUnsupported
	}
	return nil
}

// ListTemplateSetExclusions returns the catalog rows excluded by an exclude
// set, ordered like the catalog list. Other modes have no exclusion contract.
func (s *Store) ListTemplateSetExclusions(ctx context.Context, setID string) ([]Template, error) {
	if err := s.requireExcludeTemplateSetRead(ctx, setID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+tmplListCols+` FROM templates
		 JOIN template_set_exclusions e ON e.template_id = templates.id
		 WHERE e.template_set_id = $1
		 ORDER BY lower(name), id`, setID)
	if err != nil {
		return nil, fmt.Errorf("list template set exclusions: %w", err)
	}
	defer rows.Close()
	out := []Template{}
	for rows.Next() {
		t, err := scanTemplateList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListTemplateSetExclusionIDs returns the stored ids excluded by an exclude set.
// It is the lightweight form used by scan-policy resolution.
func (s *Store) ListTemplateSetExclusionIDs(ctx context.Context, setID string) ([]string, error) {
	if err := s.requireExcludeTemplateSetRead(ctx, setID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT template_id FROM template_set_exclusions
		 WHERE template_set_id = $1 ORDER BY template_id`, setID)
	if err != nil {
		return nil, fmt.Errorf("list template set exclusion ids: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ReplaceTemplateSetExclusions replaces an exclude set's exclusion list in one
// transaction. Unknown template ids return ErrInvalidRef; other modes return
// ErrTemplateSetExclusionsUnsupported.
func (s *Store) ReplaceTemplateSetExclusions(ctx context.Context, setID string, ids []string, addedBy string) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin replace template set exclusions: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireExcludeTemplateSet(ctx, tx, setID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM template_set_exclusions WHERE template_set_id = $1`, setID); err != nil {
		return 0, fmt.Errorf("clear template set exclusions: %w", err)
	}
	unique := uniqueTemplateIDs(ids)
	if err := insertTemplateSetExclusions(ctx, tx, setID, unique, addedBy); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit template set exclusions: %w", err)
	}
	return len(unique), nil
}

// insertTemplateSetExclusions inserts a deduplicated list into an existing
// transaction. The caller owns the mode check.
func insertTemplateSetExclusions(ctx context.Context, tx pgx.Tx, setID string, ids []string, addedBy string) error {
	unique := uniqueTemplateIDs(ids)
	if len(unique) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO template_set_exclusions (template_set_id, template_id, added_by)
		 SELECT $1, template_id, $3
		 FROM unnest($2::text[]) AS selected(template_id)
		 ON CONFLICT DO NOTHING`, setID, unique, nullStr(addedBy)); err != nil {
		if isForeignKeyViolation(err) {
			return ErrInvalidRef
		}
		return fmt.Errorf("insert template set exclusions: %w", err)
	}
	return nil
}

func uniqueTemplateIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func (s *Store) requireExcludeTemplateSetRead(ctx context.Context, setID string) error {
	var mode TemplateSetMode
	err := s.pool.QueryRow(ctx,
		`SELECT mode FROM template_sets WHERE id = $1`, setID,
	).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if mode != TemplateSetModeExclude {
		return ErrTemplateSetExclusionsUnsupported
	}
	return nil
}
