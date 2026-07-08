package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// FindingStatuses is the set of manual triage states a lifecycle finding can hold.
// "fixed" is the only one the ingest path auto-reverts (→ open) on re-observation.
var FindingStatuses = []string{"open", "triaged", "false_positive", "fixed"}

// ValidStatus reports whether s is an allowed triage status.
func ValidStatus(s string) bool {
	for _, v := range FindingStatuses {
		if v == s {
			return true
		}
	}
	return false
}

// dedupSep delimits the components of a dedup key. It is the ASCII unit separator,
// which cannot appear in a target id, template id, or matched-at value.
const dedupSep = "\x1f"

// DedupKey is the stable identity of a deduplicated finding: (target, template,
// matched_at) per ARCHITECTURE.md §3. Ad-hoc scans (no target) collapse to "-".
// This MUST match the backfill formula in migration 0005 exactly.
func DedupKey(targetID, templateID, matchedAt string) string {
	t := targetID
	if t == "" {
		t = "-"
	}
	return t + dedupSep + templateID + dedupSep + matchedAt
}

// IngestFinding records one finding observation: it inserts an immutable
// occurrence row (with the verbatim raw line) and upserts the deduplicated
// lifecycle entity. On a re-observation it advances last-seen and refreshes the
// denormalised display fields; a finding previously marked "fixed" is reopened
// (a regression). All three writes run in one transaction.
func (s *Store) IngestFinding(ctx context.Context, scanID, targetID string, f types.NucleiFinding, raw []byte) error {
	key := DedupKey(targetID, f.TemplateID, f.MatchedAt)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var occID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO findings (scan_id, target_id, dedup_key, template_id, name, severity, host, matched_at, type, cve, tags, raw)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`,
		scanID, nullStr(targetID), key, f.TemplateID, f.Info.Name, f.Info.Severity, f.Host, f.MatchedAt, f.Type,
		orEmpty(f.CVEs()), orEmpty(f.Info.Tags), raw,
	).Scan(&occID); err != nil {
		return fmt.Errorf("insert occurrence: %w", err)
	}

	var lcID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO finding_lifecycle
		   (dedup_key, target_id, template_id, name, severity, host, matched_at, type, cve, tags,
		    first_seen_scan, first_seen_at, last_seen_scan, last_seen_at, latest_occurrence_id, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), $11, now(), $12, 'open')
		 ON CONFLICT (dedup_key) DO UPDATE SET
		    last_seen_scan       = excluded.last_seen_scan,
		    last_seen_at         = now(),
		    name                 = excluded.name,
		    severity             = excluded.severity,
		    host                 = excluded.host,
		    matched_at           = excluded.matched_at,
		    type                 = excluded.type,
		    cve                  = excluded.cve,
		    tags                 = excluded.tags,
		    latest_occurrence_id = excluded.latest_occurrence_id,
		    status      = CASE WHEN finding_lifecycle.status = 'fixed' THEN 'open' ELSE finding_lifecycle.status END,
		    status_note = CASE WHEN finding_lifecycle.status = 'fixed'
		                       THEN 'reopened: re-observed after being marked fixed'
		                       ELSE finding_lifecycle.status_note END,
		    status_by   = CASE WHEN finding_lifecycle.status = 'fixed' THEN 'system' ELSE finding_lifecycle.status_by END,
		    status_at   = CASE WHEN finding_lifecycle.status = 'fixed' THEN now() ELSE finding_lifecycle.status_at END
		 RETURNING id`,
		key, nullStr(targetID), f.TemplateID, f.Info.Name, f.Info.Severity, f.Host, f.MatchedAt, f.Type,
		orEmpty(f.CVEs()), orEmpty(f.Info.Tags), scanID, occID,
	).Scan(&lcID); err != nil {
		return fmt.Errorf("upsert lifecycle: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE findings SET finding_id = $1 WHERE id = $2`, lcID, occID); err != nil {
		return fmt.Errorf("link occurrence: %w", err)
	}
	return tx.Commit(ctx)
}

// LifecycleRow is a deduplicated finding as returned to API callers (the triage
// view). Resolved and New are derived at read time from the target's latest
// completed scan, so they never go stale.
type LifecycleRow struct {
	ID                 int64     `json:"id"`
	TargetID           *string   `json:"target_id,omitempty"`
	TemplateID         string    `json:"template_id"`
	Name               string    `json:"name"`
	Severity           string    `json:"severity"`
	Host               string    `json:"host"`
	MatchedAt          string    `json:"matched_at"`
	Type               string    `json:"type"`
	CVE                []string  `json:"cve"`
	Tags               []string  `json:"tags"`
	Status             string    `json:"status"`
	Resolved           bool      `json:"resolved"`
	New                bool      `json:"new"`
	FirstSeenScan      *string   `json:"first_seen_scan,omitempty"`
	LastSeenScan       *string   `json:"last_seen_scan,omitempty"`
	FirstSeenAt        time.Time `json:"first_seen_at"`
	LastSeenAt         time.Time `json:"last_seen_at"`
	LatestOccurrenceID *int64    `json:"latest_occurrence_id,omitempty"`
}

// LifecycleDetail is one deduplicated finding with its full triage metadata and
// the raw Nuclei JSON of its latest occurrence, for the vulnerability detail view.
type LifecycleDetail struct {
	LifecycleRow
	StatusNote string          `json:"status_note,omitempty"`
	StatusBy   string          `json:"status_by,omitempty"`
	StatusAt   *time.Time      `json:"status_at,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// LifecycleFilter narrows and pages the deduplicated findings list.
type LifecycleFilter struct {
	TargetID   string
	Query      string   // substring on name OR template id
	Severities []string // any-of
	Host       string   // substring
	CVE        string   // substring on any CVE id
	Tag        string   // exact tag membership
	Status     string   // exact triage status
	View       string   // "" / "all" | "open" | "new" | "resolved"
	Limit      int
	Offset     int
}

// A finding is "resolved/gone" when its target has a newer completed scan than the
// one that last observed it; "new" when it first appeared in that latest scan.
// Both reference ls.latest_scan from the lateral join in lifecycleFrom.
const (
	lcResolvedExpr = `(l.target_id IS NOT NULL AND ls.latest_scan IS NOT NULL AND ls.latest_scan <> l.last_seen_scan)`
	lcNewExpr      = `(ls.latest_scan IS NOT NULL AND l.first_seen_scan = ls.latest_scan)`
	lifecycleFrom  = `FROM finding_lifecycle l
		LEFT JOIN LATERAL (
			SELECT s.id AS latest_scan FROM scans s
			WHERE s.target_id = l.target_id AND s.state = 'complete'
			ORDER BY s.created_at DESC LIMIT 1
		) ls ON l.target_id IS NOT NULL`
)

// ListLifecycleFindings returns a page of deduplicated findings (severity-sorted,
// then most-recently-seen first) plus the total matching the filter.
func (s *Store) ListLifecycleFindings(ctx context.Context, f LifecycleFilter) ([]LifecycleRow, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	var conds []string
	var args []any
	push := func(val any) int {
		args = append(args, val)
		return len(args)
	}
	if f.TargetID != "" {
		conds = append(conds, fmt.Sprintf("l.target_id = $%d", push(f.TargetID)))
	}
	if f.Query != "" {
		n := push("%" + f.Query + "%")
		conds = append(conds, fmt.Sprintf("(l.name ILIKE $%d OR l.template_id ILIKE $%d)", n, n))
	}
	if len(f.Severities) > 0 {
		lowered := make([]string, len(f.Severities))
		for i, s := range f.Severities {
			lowered[i] = strings.ToLower(s)
		}
		conds = append(conds, fmt.Sprintf("lower(l.severity) = ANY($%d)", push(lowered)))
	}
	if f.Host != "" {
		conds = append(conds, fmt.Sprintf("l.host ILIKE $%d", push("%"+f.Host+"%")))
	}
	if f.CVE != "" {
		conds = append(conds, fmt.Sprintf("EXISTS (SELECT 1 FROM unnest(l.cve) c WHERE c ILIKE $%d)", push("%"+f.CVE+"%")))
	}
	if f.Tag != "" {
		conds = append(conds, fmt.Sprintf("$%d = ANY(l.tags)", push(f.Tag)))
	}
	if f.Status != "" {
		conds = append(conds, fmt.Sprintf("l.status = $%d", push(f.Status)))
	}
	switch f.View {
	case "resolved":
		conds = append(conds, lcResolvedExpr)
	case "new":
		conds = append(conds, lcNewExpr)
	case "open":
		conds = append(conds, "l.status = 'open'", "NOT "+lcResolvedExpr)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) "+lifecycleFrom+" "+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitPH := push(f.Limit)
	offsetPH := push(f.Offset)
	query := fmt.Sprintf(
		`SELECT l.id, l.target_id, l.template_id, l.name, l.severity, l.host, l.matched_at, l.type,
		        l.cve, l.tags, l.status, l.first_seen_scan, l.last_seen_scan, l.first_seen_at, l.last_seen_at,
		        l.latest_occurrence_id, %s AS resolved, %s AS is_new
		 %s %s
		 ORDER BY %s DESC, l.last_seen_at DESC, l.id DESC
		 LIMIT $%d OFFSET $%d`,
		lcResolvedExpr, lcNewExpr, lifecycleFrom, where, severityOrder, limitPH, offsetPH)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []LifecycleRow
	for rows.Next() {
		var r LifecycleRow
		if err := rows.Scan(&r.ID, &r.TargetID, &r.TemplateID, &r.Name, &r.Severity, &r.Host,
			&r.MatchedAt, &r.Type, &r.CVE, &r.Tags, &r.Status, &r.FirstSeenScan, &r.LastSeenScan,
			&r.FirstSeenAt, &r.LastSeenAt, &r.LatestOccurrenceID, &r.Resolved, &r.New); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// GetLifecycleFinding returns one deduplicated finding by id, including triage
// metadata and the raw Nuclei JSON of its latest occurrence.
func (s *Store) GetLifecycleFinding(ctx context.Context, id int64) (LifecycleDetail, error) {
	var d LifecycleDetail
	var note, by *string
	query := fmt.Sprintf(
		`SELECT l.id, l.target_id, l.template_id, l.name, l.severity, l.host, l.matched_at, l.type,
		        l.cve, l.tags, l.status, l.first_seen_scan, l.last_seen_scan, l.first_seen_at, l.last_seen_at,
		        l.latest_occurrence_id, %s AS resolved, %s AS is_new,
		        l.status_note, l.status_by, l.status_at, o.raw
		 %s
		 LEFT JOIN findings o ON o.id = l.latest_occurrence_id
		 WHERE l.id = $1`,
		lcResolvedExpr, lcNewExpr, lifecycleFrom)
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&d.ID, &d.TargetID, &d.TemplateID, &d.Name, &d.Severity, &d.Host, &d.MatchedAt, &d.Type,
		&d.CVE, &d.Tags, &d.Status, &d.FirstSeenScan, &d.LastSeenScan, &d.FirstSeenAt, &d.LastSeenAt,
		&d.LatestOccurrenceID, &d.Resolved, &d.New, &note, &by, &d.StatusAt, &d.Raw)
	if err != nil {
		if err == pgx.ErrNoRows {
			return LifecycleDetail{}, ErrNotFound
		}
		return LifecycleDetail{}, err
	}
	d.StatusNote = deref(note)
	d.StatusBy = deref(by)
	return d, nil
}

// UpdateFindingStatus sets the triage status (and note/actor) of a lifecycle
// finding. The caller must have validated status with ValidStatus.
func (s *Store) UpdateFindingStatus(ctx context.Context, id int64, status, note, by string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE finding_lifecycle SET status = $1, status_note = $2, status_by = $3, status_at = now() WHERE id = $4`,
		status, nullStr(note), nullStr(by), id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
