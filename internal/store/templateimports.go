package store

import (
	"context"
	"fmt"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TemplateImportWrite is one already-validated custom template mutation.
// Overwrite is true only when import conflict policy explicitly selected it.
type TemplateImportWrite struct {
	Template  Template
	Overwrite bool
}

// TemplateSetImportWrite optionally creates or replaces one explicit set in
// the same transaction as its custom templates. ExistingID empty means create.
type TemplateSetImportWrite struct {
	ExistingID          string
	Name                string
	Mode                TemplateSetMode
	TemplateIDs         []string
	ExcludedTemplateIDs []string
}

// ApplyTemplateImport commits a validated portability import atomically. The
// HTTP layer parses archives and resolves skip/overwrite/rename semantics; this
// method is the final race-safe write boundary. A concurrent uniqueness change
// is reported as ErrConflict rather than silently changing the chosen policy.
func (s *Store) ApplyTemplateImport(
	ctx context.Context,
	writes []TemplateImportWrite,
	setWrite *TemplateSetImportWrite,
	actor string,
) (*TemplateSet, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin template import: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var setMode TemplateSetMode
	if setWrite != nil {
		var err error
		setMode, err = normalizeTemplateSetMode(setWrite.Mode)
		if err != nil {
			return nil, err
		}
		if setMode != TemplateSetModeExclude && len(setWrite.ExcludedTemplateIDs) > 0 {
			return nil, ErrTemplateSetExclusionsUnsupported
		}
		if setMode != TemplateSetModeExact && len(setWrite.TemplateIDs) > 0 {
			return nil, ErrTemplateSetNonExact
		}
	}

	for _, write := range writes {
		t := write.Template
		if write.Overwrite {
			tag, err := tx.Exec(ctx,
				`UPDATE templates SET path = $2, yaml = $3, content_sha256 = $4,
				   name = $5, author = $6, severity = $7, description = $8,
				   tags = $9, revision = revision + 1, updated_at = now()
				 WHERE id = $1 AND source = 'custom'`,
				t.ID, t.Path, t.YAML, t.ContentSHA256, t.Name, t.Author,
				t.Severity, t.Description, orEmpty(t.Tags))
			if err != nil {
				return nil, fmt.Errorf("overwrite imported template %q: %w", t.ID, err)
			}
			if tag.RowsAffected() != 1 {
				return nil, ErrConflict
			}
			continue
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO templates (id, source, path, yaml, content_sha256, name, author,
			   severity, description, tags, revision, availability, created_by)
			 VALUES ($1, 'custom', $2, $3, $4, $5, $6, $7, $8, $9, 1, 'active', $10)`,
			t.ID, t.Path, t.YAML, t.ContentSHA256, t.Name, t.Author,
			t.Severity, t.Description, orEmpty(t.Tags), nullStr(actor))
		if err != nil {
			if isUniqueViolation(err) {
				return nil, ErrConflict
			}
			return nil, fmt.Errorf("insert imported template %q: %w", t.ID, err)
		}
	}

	if setWrite == nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit template import: %w", err)
		}
		return nil, nil
	}

	setID := setWrite.ExistingID
	if setID == "" {
		setID = types.NewID()
		_, err := tx.Exec(ctx,
			`INSERT INTO template_sets (id, name, mode, created_by) VALUES ($1, $2, $3, $4)`,
			setID, setWrite.Name, setMode, nullStr(actor))
		if err != nil {
			if isUniqueViolation(err) {
				return nil, ErrConflict
			}
			return nil, fmt.Errorf("insert imported template set: %w", err)
		}
		if setMode == TemplateSetModeExclude && len(setWrite.ExcludedTemplateIDs) > 0 {
			if err := insertTemplateSetExclusions(ctx, tx, setID, setWrite.ExcludedTemplateIDs, actor); err != nil {
				return nil, fmt.Errorf("insert imported template set exclusions: %w", err)
			}
		}
	} else {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT true FROM template_sets WHERE id = $1 FOR UPDATE`, setID,
		).Scan(&exists); err != nil {
			return nil, err
		}
		_, err := tx.Exec(ctx,
			`UPDATE template_sets SET name = $2, mode = $3, updated_at = now() WHERE id = $1`,
			setID, setWrite.Name, setMode)
		if err != nil {
			if isUniqueViolation(err) {
				return nil, ErrConflict
			}
			return nil, fmt.Errorf("update imported template set: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM template_set_members WHERE template_set_id = $1`, setID); err != nil {
			return nil, fmt.Errorf("clear imported template set: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM template_set_exclusions WHERE template_set_id = $1`, setID); err != nil {
			return nil, fmt.Errorf("clear imported template set exclusions: %w", err)
		}
		if setMode == TemplateSetModeExclude && len(setWrite.ExcludedTemplateIDs) > 0 {
			if err := insertTemplateSetExclusions(ctx, tx, setID, setWrite.ExcludedTemplateIDs, actor); err != nil {
				return nil, fmt.Errorf("insert imported template set exclusions: %w", err)
			}
		}
	}
	if setMode == TemplateSetModeExact && len(setWrite.TemplateIDs) > 0 {
		_, err := tx.Exec(ctx,
			`INSERT INTO template_set_members (template_set_id, template_id, added_by)
			 SELECT $1, template_id, $3
			 FROM unnest($2::text[]) AS imported(template_id)`,
			setID, setWrite.TemplateIDs, nullStr(actor))
		if err != nil {
			if isForeignKeyViolation(err) {
				return nil, ErrInvalidRef
			}
			return nil, fmt.Errorf("insert imported template set members: %w", err)
		}
	}
	out, err := scanTemplateSet(tx.QueryRow(ctx,
		`SELECT `+tmplSetCols+` FROM template_sets WHERE id = $1`, setID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit template set import: %w", err)
	}
	return &out, nil
}
