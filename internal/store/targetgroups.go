package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TargetGroup is a named static set of targets (#13). Members is a summary of
// the member targets (populated on reads); writes take a list of target ids. A
// group is a convenience subset of the scope allowlist, not a new scope source.
type TargetGroup struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Members   []TargetGroupMember `json:"members"`
	CreatedBy string              `json:"created_by,omitempty"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}

// TargetGroupMember is a lightweight summary of one member target.
type TargetGroupMember struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	HostCount int    `json:"host_count"`
}

// CreateTargetGroup inserts a group and its membership atomically. A duplicate
// name yields ErrConflict; an unknown target id yields ErrInvalidRef.
func (s *Store) CreateTargetGroup(ctx context.Context, name, createdBy string, targetIDs []string) (TargetGroup, error) {
	id := types.NewID()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TargetGroup{}, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO target_groups (id, name, created_by) VALUES ($1, $2, $3)`,
		id, name, nullStr(createdBy),
	); err != nil {
		if isUniqueViolation(err) {
			return TargetGroup{}, ErrConflict
		}
		return TargetGroup{}, fmt.Errorf("insert target group: %w", err)
	}
	if err := insertGroupMembers(ctx, tx, id, targetIDs); err != nil {
		return TargetGroup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TargetGroup{}, err
	}
	return s.GetTargetGroup(ctx, id)
}

// UpdateTargetGroup renames a group and replaces its membership atomically.
func (s *Store) UpdateTargetGroup(ctx context.Context, id, name string, targetIDs []string) (TargetGroup, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TargetGroup{}, err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx,
		`UPDATE target_groups SET name = $2, updated_at = now() WHERE id = $1`, id, name)
	if err != nil {
		if isUniqueViolation(err) {
			return TargetGroup{}, ErrConflict
		}
		return TargetGroup{}, fmt.Errorf("update target group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return TargetGroup{}, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM target_group_members WHERE group_id = $1`, id); err != nil {
		return TargetGroup{}, fmt.Errorf("clear group members: %w", err)
	}
	if err := insertGroupMembers(ctx, tx, id, targetIDs); err != nil {
		return TargetGroup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TargetGroup{}, err
	}
	return s.GetTargetGroup(ctx, id)
}

// insertGroupMembers adds membership rows, mapping a bad target id (FK) to
// ErrInvalidRef. Empty membership is allowed (a group can start empty).
func insertGroupMembers(ctx context.Context, tx pgx.Tx, groupID string, targetIDs []string) error {
	for _, tid := range targetIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO target_group_members (group_id, target_id) VALUES ($1, $2)
			 ON CONFLICT DO NOTHING`, groupID, tid,
		); err != nil {
			if isForeignKeyViolation(err) {
				return ErrInvalidRef
			}
			return fmt.Errorf("insert group member: %w", err)
		}
	}
	return nil
}

// GetTargetGroup returns one group with its member summaries, or ErrNotFound.
func (s *Store) GetTargetGroup(ctx context.Context, id string) (TargetGroup, error) {
	var g TargetGroup
	var createdBy *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, created_by, created_at, updated_at FROM target_groups WHERE id = $1`, id,
	).Scan(&g.ID, &g.Name, &createdBy, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TargetGroup{}, ErrNotFound
		}
		return TargetGroup{}, err
	}
	g.CreatedBy = deref(createdBy)
	members, err := s.groupMembers(ctx, id)
	if err != nil {
		return TargetGroup{}, err
	}
	g.Members = members
	return g, nil
}

// ListTargetGroups returns all groups (with member summaries) ordered by name.
func (s *Store) ListTargetGroups(ctx context.Context) ([]TargetGroup, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, created_by, created_at, updated_at FROM target_groups ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TargetGroup
	for rows.Next() {
		var g TargetGroup
		var createdBy *string
		if err := rows.Scan(&g.ID, &g.Name, &createdBy, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		g.CreatedBy = deref(createdBy)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Populate members per group (small N for an internal-team tool).
	for i := range out {
		members, err := s.groupMembers(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Members = members
	}
	return out, nil
}

// groupMembers returns the member summaries for a group, ordered by target name.
func (s *Store) groupMembers(ctx context.Context, groupID string) ([]TargetGroupMember, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT t.id, t.name, coalesce(array_length(t.hosts, 1), 0)
		   FROM target_group_members m
		   JOIN targets t ON t.id = m.target_id
		  WHERE m.group_id = $1
		  ORDER BY lower(t.name)`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	members := []TargetGroupMember{}
	for rows.Next() {
		var m TargetGroupMember
		if err := rows.Scan(&m.ID, &m.Name, &m.HostCount); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// GroupMemberTargets resolves a group to its full member Target rows, for scan
// fan-out. Returns ErrNotFound if the group is unknown. An empty group returns
// an empty slice (the caller rejects dispatching nothing).
func (s *Store) GroupMemberTargets(ctx context.Context, groupID string) ([]Target, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM target_groups WHERE id = $1)`, groupID,
	).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx,
		`SELECT t.id, t.name, t.hosts, t.tags, t.created_by, t.created_at, t.updated_at
		   FROM target_group_members m
		   JOIN targets t ON t.id = m.target_id
		  WHERE m.group_id = $1
		  ORDER BY lower(t.name)`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Target
	for rows.Next() {
		var t Target
		var createdBy *string
		if err := rows.Scan(&t.ID, &t.Name, &t.Hosts, &t.Tags, &createdBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.CreatedBy = deref(createdBy)
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTargetGroup removes a group (membership rows cascade). ErrNotFound if
// absent. Deleting a group referenced by a schedule cascades to the schedule
// (target_group_id ON DELETE CASCADE), matching how a single target does today.
func (s *Store) DeleteTargetGroup(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM target_groups WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
