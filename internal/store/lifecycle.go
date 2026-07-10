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

// Dispositions is the set of manual analyst overlays a finding can carry (Tenable
// Security Center-style). Closure itself is evidence-driven — there is no manual
// "fixed"; a finding the latest scan no longer sees becomes Mitigated on its own.
var Dispositions = []string{"none", "false_positive", "accepted"}

// Severities is the ordered severity vocabulary, used to validate a Recast Risk.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// ValidDisposition reports whether d is an allowed analyst disposition.
func ValidDisposition(d string) bool { return contains(Dispositions, d) }

// ValidSeverity reports whether s is an allowed severity (for a recast).
func ValidSeverity(s string) bool { return contains(Severities, s) }

func contains(set []string, v string) bool {
	for _, x := range set {
		if x == v {
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
// lifecycle entity. On a re-observation it advances last-seen and, if the finding
// had been Mitigated (absent from the target's previous scan) and is now back, it
// bumps times_mitigated — which drives the Resurfaced / Previously-Mitigated
// detection states. Analyst dispositions are left untouched (an accepted risk stays
// accepted until it expires). All writes run in one transaction.
func (s *Store) IngestFinding(ctx context.Context, scanID, targetID string, f types.NucleiFinding, raw []byte) error {
	key := DedupKey(targetID, f.TemplateID, f.MatchedAt)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// The target's most recent completed scan *before* this one. If a pre-existing
	// finding's last-seen isn't that scan, it was gone in between and is resurfacing.
	var prevLatest *string
	if targetID != "" {
		var id string
		err := tx.QueryRow(ctx,
			`SELECT id::text FROM scans
			 WHERE target_id = $1 AND state = 'complete' AND id <> $2
			 ORDER BY created_at DESC LIMIT 1`, targetID, scanID).Scan(&id)
		if err == nil {
			prevLatest = &id
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("prev scan lookup: %w", err)
		}
	}

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
		    first_seen_scan, first_seen_at, last_seen_scan, last_seen_at, latest_occurrence_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), $11, now(), $12)
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
		    times_mitigated      = finding_lifecycle.times_mitigated + CASE
		        WHEN $13::uuid IS NOT NULL
		         AND finding_lifecycle.last_seen_scan IS DISTINCT FROM $13::uuid
		         AND finding_lifecycle.last_seen_scan IS DISTINCT FROM $11::uuid
		        THEN 1 ELSE 0 END
		 RETURNING id`,
		key, nullStr(targetID), f.TemplateID, f.Info.Name, f.Info.Severity, f.Host, f.MatchedAt, f.Type,
		orEmpty(f.CVEs()), orEmpty(f.Info.Tags), scanID, occID, prevLatest,
	).Scan(&lcID); err != nil {
		return fmt.Errorf("upsert lifecycle: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE findings SET finding_id = $1 WHERE id = $2`, lcID, occID); err != nil {
		return fmt.Errorf("link occurrence: %w", err)
	}
	return tx.Commit(ctx)
}

// lifecycle read-time expressions. All reference l (finding_lifecycle) and ls
// (the target's latest completed scan, from the lateral join in lifecycleFrom).
const (
	// lcDetectionExpr derives the Tenable-style detection state purely from scan
	// observation. Ad-hoc findings (no target scope) are always "active".
	lcDetectionExpr = `CASE
		WHEN ls.latest_scan IS NULL THEN 'active'
		WHEN l.last_seen_scan IS DISTINCT FROM ls.latest_scan
			THEN CASE WHEN l.times_mitigated >= 1 THEN 'previously_mitigated' ELSE 'mitigated' END
		WHEN l.first_seen_scan = ls.latest_scan THEN 'new'
		WHEN l.times_mitigated >= 1 THEN 'resurfaced'
		ELSE 'active'
	END`

	// lcEffectiveExpr overlays the analyst disposition onto the detection state.
	// An accepted risk past its expiry falls through to the detection state.
	lcEffectiveExpr = `CASE
		WHEN l.disposition = 'accepted' AND (l.accept_expires_at IS NULL OR l.accept_expires_at > now()) THEN 'accepted'
		WHEN l.disposition = 'false_positive' THEN 'false_positive'
		ELSE (` + lcDetectionExpr + `)
	END`

	// effSevExpr is the severity shown/sorted on: a recast wins over the observed one.
	effSevExpr  = `coalesce(l.recast_severity, l.severity)`
	effSevOrder = `CASE lower(coalesce(l.recast_severity, l.severity))
		WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END`
	lifecycleFrom = `FROM finding_lifecycle l
		LEFT JOIN LATERAL (
			SELECT s.id AS latest_scan FROM scans s
			WHERE s.target_id = l.target_id AND s.state = 'complete'
			ORDER BY s.created_at DESC LIMIT 1
		) ls ON l.target_id IS NOT NULL`
)

// LifecycleRow is a deduplicated finding as returned to API callers (the triage
// view). DetectionState and EffectiveState are derived server-side from scan
// history + disposition; EffectiveSeverity honours a recast.
type LifecycleRow struct {
	ID                 int64      `json:"id"`
	TargetID           *string    `json:"target_id,omitempty"`
	TemplateID         string     `json:"template_id"`
	Name               string     `json:"name"`
	Severity           string     `json:"severity"`
	RecastSeverity     *string    `json:"recast_severity,omitempty"`
	EffectiveSeverity  string     `json:"effective_severity"`
	Host               string     `json:"host"`
	MatchedAt          string     `json:"matched_at"`
	Type               string     `json:"type"`
	CVE                []string   `json:"cve"`
	Tags               []string   `json:"tags"`
	Disposition        string     `json:"disposition"`
	AcceptExpiresAt    *time.Time `json:"accept_expires_at,omitempty"`
	DetectionState     string     `json:"detection_state"`
	EffectiveState     string     `json:"effective_state"`
	TimesMitigated     int        `json:"times_mitigated"`
	FirstSeenScan      *string    `json:"first_seen_scan,omitempty"`
	LastSeenScan       *string    `json:"last_seen_scan,omitempty"`
	FirstSeenAt        time.Time  `json:"first_seen_at"`
	LastSeenAt         time.Time  `json:"last_seen_at"`
	LatestOccurrenceID *int64     `json:"latest_occurrence_id,omitempty"`
}

// LifecycleDetail is one deduplicated finding with its disposition/recast audit
// trail and the raw Nuclei JSON of its latest occurrence, for the detail view.
type LifecycleDetail struct {
	LifecycleRow
	DispositionNote string          `json:"disposition_note,omitempty"`
	DispositionBy   string          `json:"disposition_by,omitempty"`
	DispositionAt   *time.Time      `json:"disposition_at,omitempty"`
	RecastNote      string          `json:"recast_note,omitempty"`
	RecastBy        string          `json:"recast_by,omitempty"`
	RecastAt        *time.Time      `json:"recast_at,omitempty"`
	Raw             json.RawMessage `json:"raw,omitempty"`
}

// LifecycleFilter narrows and pages the deduplicated findings list.
type LifecycleFilter struct {
	TargetID    string
	Query       string   // substring on name OR template id
	Severities  []string // any-of, matched against the effective (recast-aware) severity
	Host        string   // substring
	CVE         string   // substring on any CVE id
	Tag         string   // exact tag membership
	Disposition string   // exact disposition (none|false_positive|accepted)
	State       string   // exact effective state (new|active|resurfaced|mitigated|previously_mitigated|accepted|false_positive)
	Limit       int
	Offset      int
}

// lcSelectCols is the projection shared by list + detail (up to the raw payload).
const lcSelectCols = `l.id, l.target_id, l.template_id, l.name, l.severity, l.recast_severity,
	` + effSevExpr + ` AS eff_sev, l.host, l.matched_at, l.type, l.cve, l.tags,
	l.disposition, l.accept_expires_at, ` + lcDetectionExpr + ` AS detection_state,
	` + lcEffectiveExpr + ` AS effective_state, l.times_mitigated,
	l.first_seen_scan, l.last_seen_scan, l.first_seen_at, l.last_seen_at, l.latest_occurrence_id`

func scanLifecycleRow(row pgx.Row, r *LifecycleRow) error {
	return row.Scan(&r.ID, &r.TargetID, &r.TemplateID, &r.Name, &r.Severity, &r.RecastSeverity,
		&r.EffectiveSeverity, &r.Host, &r.MatchedAt, &r.Type, &r.CVE, &r.Tags,
		&r.Disposition, &r.AcceptExpiresAt, &r.DetectionState, &r.EffectiveState, &r.TimesMitigated,
		&r.FirstSeenScan, &r.LastSeenScan, &r.FirstSeenAt, &r.LastSeenAt, &r.LatestOccurrenceID)
}

// lifecycleWhere builds the shared WHERE clause for the lifecycle filter,
// appending its bind values onto *args (owned by the caller, so callers can push
// further LIMIT/OFFSET placeholders onto the same slice with correct `$N`).
func lifecycleWhere(f LifecycleFilter, args *[]any) (where string) {
	push := func(val any) int {
		*args = append(*args, val)
		return len(*args)
	}
	var conds []string
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
		conds = append(conds, fmt.Sprintf("lower(%s) = ANY($%d)", effSevExpr, push(lowered)))
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
	if f.Disposition != "" {
		conds = append(conds, fmt.Sprintf("l.disposition = $%d", push(f.Disposition)))
	}
	if f.State != "" {
		conds = append(conds, fmt.Sprintf("(%s) = $%d", lcEffectiveExpr, push(f.State)))
	}
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	return where
}

// lcOrderBy is the shared sort: highest effective severity first, then most
// recently seen. Kept identical across list + export so an export matches the UI.
const lcOrderBy = ` ORDER BY ` + effSevOrder + ` DESC, l.last_seen_at DESC, l.id DESC`

// exportMaxRows caps an export so a pathological filter can't OOM the backend.
const exportMaxRows = 50000

// ListLifecycleFindings returns a page of deduplicated findings (severity-sorted,
// then most-recently-seen first) plus the total matching the filter.
func (s *Store) ListLifecycleFindings(ctx context.Context, f LifecycleFilter) ([]LifecycleRow, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	var args []any
	where := lifecycleWhere(f, &args)

	var total int
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) "+lifecycleFrom+" "+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, f.Limit)
	limitPH := len(args)
	args = append(args, f.Offset)
	offsetPH := len(args)
	query := fmt.Sprintf(`SELECT %s %s %s%s LIMIT $%d OFFSET $%d`,
		lcSelectCols, lifecycleFrom, where, lcOrderBy, limitPH, offsetPH)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []LifecycleRow
	for rows.Next() {
		var r LifecycleRow
		if err := scanLifecycleRow(rows, &r); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ExportLifecycleFindings returns all deduplicated findings matching the filter
// (up to exportMaxRows), in the same order as the list — for bulk export. The
// filter's Limit/Offset are ignored.
func (s *Store) ExportLifecycleFindings(ctx context.Context, f LifecycleFilter) ([]LifecycleRow, error) {
	var args []any
	where := lifecycleWhere(f, &args)
	args = append(args, exportMaxRows)
	limitPH := len(args)
	query := fmt.Sprintf(`SELECT %s %s %s%s LIMIT $%d`,
		lcSelectCols, lifecycleFrom, where, lcOrderBy, limitPH)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LifecycleRow
	for rows.Next() {
		var r LifecycleRow
		if err := scanLifecycleRow(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ExportLifecycleRaw returns the verbatim Nuclei JSON of each matching finding's
// latest occurrence (same filter + order as the list), for a raw JSONL export.
// Findings whose latest occurrence is missing are skipped (INNER JOIN).
func (s *Store) ExportLifecycleRaw(ctx context.Context, f LifecycleFilter) ([]json.RawMessage, error) {
	var args []any
	where := lifecycleWhere(f, &args)
	args = append(args, exportMaxRows)
	limitPH := len(args)
	query := fmt.Sprintf(`SELECT o.raw %s JOIN findings o ON o.id = l.latest_occurrence_id %s%s LIMIT $%d`,
		lifecycleFrom, where, lcOrderBy, limitPH)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []json.RawMessage
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

// GetLifecycleFinding returns one deduplicated finding by id, including the
// disposition/recast audit trail and the raw JSON of its latest occurrence.
func (s *Store) GetLifecycleFinding(ctx context.Context, id int64) (LifecycleDetail, error) {
	var d LifecycleDetail
	var dNote, dBy, rNote, rBy *string
	query := fmt.Sprintf(
		`SELECT %s, l.disposition_note, l.disposition_by, l.disposition_at,
		        l.recast_note, l.recast_by, l.recast_at, o.raw
		 %s
		 LEFT JOIN findings o ON o.id = l.latest_occurrence_id
		 WHERE l.id = $1`, lcSelectCols, lifecycleFrom)
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&d.ID, &d.TargetID, &d.TemplateID, &d.Name, &d.Severity, &d.RecastSeverity,
		&d.EffectiveSeverity, &d.Host, &d.MatchedAt, &d.Type, &d.CVE, &d.Tags,
		&d.Disposition, &d.AcceptExpiresAt, &d.DetectionState, &d.EffectiveState, &d.TimesMitigated,
		&d.FirstSeenScan, &d.LastSeenScan, &d.FirstSeenAt, &d.LastSeenAt, &d.LatestOccurrenceID,
		&dNote, &dBy, &d.DispositionAt, &rNote, &rBy, &d.RecastAt, &d.Raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LifecycleDetail{}, ErrNotFound
		}
		return LifecycleDetail{}, err
	}
	d.DispositionNote, d.DispositionBy = deref(dNote), deref(dBy)
	d.RecastNote, d.RecastBy = deref(rNote), deref(rBy)
	return d, nil
}

// SetDisposition applies an analyst disposition (none / false_positive / accepted).
// expiresAt is honoured only for 'accepted' (an optional Accept-Risk expiry); it is
// cleared otherwise. The caller must have validated disposition with ValidDisposition.
func (s *Store) SetDisposition(ctx context.Context, id int64, disposition, note, by string, expiresAt *time.Time) error {
	if disposition != "accepted" {
		expiresAt = nil
	}
	ct, err := s.pool.Exec(ctx,
		`UPDATE finding_lifecycle
		   SET disposition = $1, accept_expires_at = $2,
		       disposition_note = $3, disposition_by = $4, disposition_at = now()
		 WHERE id = $5`,
		disposition, expiresAt, nullStr(note), nullStr(by), id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecastSeverity overrides (or, with severity == "", clears) a finding's severity.
// The caller must have validated a non-empty severity with ValidSeverity.
func (s *Store) RecastSeverity(ctx context.Context, id int64, severity, note, by string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE finding_lifecycle
		   SET recast_severity = $1, recast_note = $2, recast_by = $3, recast_at = now()
		 WHERE id = $4`,
		nullStr(severity), nullStr(note), nullStr(by), id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
