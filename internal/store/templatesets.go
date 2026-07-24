package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// LegacyTemplateFilter preserves the retired POC selector long enough to
// materialize a legacy set against the current active catalog. It is a snapshot,
// not an accepted create/update contract.
type LegacyTemplateFilter struct {
	GitRef     string   `json:"git_ref,omitempty"`
	Severities []string `json:"severities"`
	Tags       []string `json:"tags"`
	Paths      []string `json:"paths"`
}

// TemplateSet selects which Nuclei templates a scan runs. New and converted
// sets are driven exclusively by template_set_members. LegacyFilterSnapshot is
// read-only migration context for the one-click conversion action.
type TemplateSet struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	LegacyFilter         bool                  `json:"legacy_filter"`
	LegacyFilterSnapshot *LegacyTemplateFilter `json:"legacy_filter_snapshot,omitempty"`
	MemberCount          int                   `json:"member_count"`
	CreatedBy            string                `json:"created_by,omitempty"`
	CreatedAt            time.Time             `json:"created_at"`
	UpdatedAt            time.Time             `json:"updated_at"`
}

// tmplSetCols is the read projection shared by Get/List/Update. member_count is
// a correlated subquery so a set's size is always live even as members change.
const tmplSetCols = `id, name, legacy_filter, legacy_filter_snapshot,
	(SELECT count(*) FROM template_set_members m WHERE m.template_set_id = template_sets.id),
	created_by, created_at, updated_at`

// CreateTemplateSet inserts a template set and returns it populated.
func (s *Store) CreateTemplateSet(ctx context.Context, in TemplateSet) (TemplateSet, error) {
	in.ID = types.NewID()
	err := s.pool.QueryRow(ctx,
		`INSERT INTO template_sets (id, name, created_by)
		 VALUES ($1, $2, $3)
		 RETURNING created_at, updated_at`,
		in.ID, in.Name, nullStr(in.CreatedBy),
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
	if err := requireExplicitTemplateSet(ctx, tx, id); err != nil {
		return TemplateSet{}, err
	}
	t, err := scanTemplateSet(tx.QueryRow(ctx,
		`UPDATE template_sets
		 SET name = $2, updated_at = now()
		 WHERE id = $1
		 RETURNING `+tmplSetCols,
		id, in.Name))
	if err != nil {
		if isUniqueViolation(err) {
			return TemplateSet{}, ErrConflict
		}
		return TemplateSet{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TemplateSet{}, fmt.Errorf("commit update template set: %w", err)
	}
	return t, nil
}

// ConvertLegacyTemplateSet atomically resolves a retired filter snapshot
// against the current active upstream catalog, inserts the exact matching ids,
// and clears the legacy flag. Legacy filters selected only from the community
// repository, so conversion never sweeps custom templates into an old set.
// GitRef is retained in the snapshot for operator context but intentionally
// does not constrain conversion: the catalog's configured global pin is now the
// only available source of upstream truth.
func (s *Store) ConvertLegacyTemplateSet(ctx context.Context, id, addedBy string) (TemplateSet, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TemplateSet{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var legacy bool
	var raw []byte
	err = tx.QueryRow(ctx,
		`SELECT legacy_filter, legacy_filter_snapshot
		 FROM template_sets WHERE id = $1 FOR UPDATE`, id,
	).Scan(&legacy, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateSet{}, ErrNotFound
	}
	if err != nil {
		return TemplateSet{}, fmt.Errorf("read legacy template set: %w", err)
	}
	if !legacy {
		return TemplateSet{}, ErrTemplateSetNotLegacy
	}
	var filter LegacyTemplateFilter
	if len(raw) == 0 {
		return TemplateSet{}, errors.New("legacy template set has no filter snapshot")
	}
	if err := json.Unmarshal(raw, &filter); err != nil {
		return TemplateSet{}, fmt.Errorf("decode legacy filter snapshot: %w", err)
	}

	where, args := legacyTemplateFilterWhere(filter)
	rows, err := tx.Query(ctx, `SELECT id FROM templates WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return TemplateSet{}, fmt.Errorf("resolve legacy template set: %w", err)
	}
	var templateIDs []string
	for rows.Next() {
		var templateID string
		if err := rows.Scan(&templateID); err != nil {
			rows.Close()
			return TemplateSet{}, err
		}
		templateIDs = append(templateIDs, templateID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return TemplateSet{}, err
	}
	rows.Close()
	if len(templateIDs) == 0 {
		return TemplateSet{}, ErrNoTemplateMatches
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM template_set_members WHERE template_set_id = $1`, id); err != nil {
		return TemplateSet{}, fmt.Errorf("clear legacy template set members: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO template_set_members (template_set_id, template_id, added_by)
		 SELECT $1, template_id, $3
		 FROM unnest($2::text[]) AS selected(template_id)
		 ON CONFLICT DO NOTHING`, id, templateIDs, nullStr(addedBy)); err != nil {
		return TemplateSet{}, fmt.Errorf("insert converted template set members: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE template_sets
		 SET legacy_filter = false, legacy_filter_snapshot = NULL, updated_at = now()
		 WHERE id = $1`, id); err != nil {
		return TemplateSet{}, fmt.Errorf("finish legacy template set conversion: %w", err)
	}
	out, err := scanTemplateSet(tx.QueryRow(ctx,
		`SELECT `+tmplSetCols+` FROM template_sets WHERE id = $1`, id))
	if err != nil {
		return TemplateSet{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TemplateSet{}, err
	}
	return out, nil
}

// legacyTemplateFilterWhere builds the parameterized catalog predicate used by
// conversion. Severity and tag lists are any-of; the dimensions combine with
// AND. A selected path matches that file or every file below that directory.
func legacyTemplateFilterWhere(filter LegacyTemplateFilter) (string, []any) {
	conds := []string{"availability = 'active'", "source = 'upstream'"}
	var args []any
	push := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if len(filter.Severities) > 0 {
		lowered := make([]string, len(filter.Severities))
		for i, severity := range filter.Severities {
			lowered[i] = strings.ToLower(severity)
		}
		conds = append(conds, "lower(severity) = ANY("+push(lowered)+")")
	}
	if len(filter.Tags) > 0 {
		conds = append(conds, "tags && "+push(filter.Tags))
	}
	if len(filter.Paths) > 0 {
		paths := make([]string, len(filter.Paths))
		for i, path := range filter.Paths {
			paths[i] = strings.TrimSuffix(path, "/")
		}
		p := push(paths)
		conds = append(conds,
			"(path = ANY("+p+") OR EXISTS (SELECT 1 FROM unnest("+p+"::text[]) AS selected(prefix)"+
				" WHERE starts_with(path, selected.prefix || '/')))")
	}
	return strings.Join(conds, " AND "), args
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

// scanTemplateSet reads one row (projected with tmplSetCols) into a TemplateSet.
func scanTemplateSet(row pgx.Row) (TemplateSet, error) {
	var t TemplateSet
	var raw []byte
	var createdBy *string
	err := row.Scan(&t.ID, &t.Name, &t.LegacyFilter, &raw,
		&t.MemberCount, &createdBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TemplateSet{}, ErrNotFound
		}
		return TemplateSet{}, err
	}
	if len(raw) > 0 {
		t.LegacyFilterSnapshot = &LegacyTemplateFilter{}
		if err := json.Unmarshal(raw, t.LegacyFilterSnapshot); err != nil {
			return TemplateSet{}, fmt.Errorf("decode legacy filter snapshot: %w", err)
		}
	}
	t.CreatedBy = deref(createdBy)
	return t, nil
}
