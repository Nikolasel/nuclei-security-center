package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// dedupSep delimits the components of a dedup key. It is the ASCII unit
// separator, which cannot appear in a template id or matched-at value.
const dedupSep = "\x1f"

// DedupKey is the global stable identity of a lifecycle finding:
// (template, matched_at, result discriminator) per ARCHITECTURE.md §3. Scan and
// target are occurrence provenance, not identity, so observations of the same
// concrete result merge across both. The discriminator is empty for ordinary
// single-result events.
//
// matched_at is influenced by the scanned host and is not otherwise validated for
// control characters, so each component is first stripped of them — including the
// 0x1f separator itself. Without this, a crafted matched_at embedding 0x1f could
// shift the component boundaries and forge a collision with a different
// (template, matched_at) tuple, merging/overwriting its lifecycle entity
// (CWE-345/CWE-707). Real components (UUIDs, Nuclei template ids, URL matched-at)
// carry no control characters, so this is a no-op for them. Persisted keys are
// generated through this function before database writes.
func DedupKey(templateID, matchedAt, resultDiscriminator string) string {
	key := sanitizeKeyComponent(templateID) + dedupSep + sanitizeKeyComponent(matchedAt)
	if resultDiscriminator != "" {
		key += dedupSep + sanitizeKeyComponent(resultDiscriminator)
	}
	return key
}

// sanitizeKeyComponent drops ASCII control characters (C0 range plus DEL),
// guaranteeing no component can contain the dedup separator and so keeping the
// delimiter-joined key injective.
func sanitizeKeyComponent(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// FindingRecordError marks an ingest failure that is proven to be local to one
// source record. Callers may skip this record, but must continue to propagate
// every other error so database and transaction failures remain scan-fatal.
type FindingRecordError struct {
	stage string
	err   error
}

// NewFindingRecordError wraps a source-record validation/projection failure for
// the orchestrator's explicit, fail-closed classification.
func NewFindingRecordError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &FindingRecordError{stage: stage, err: err}
}

func (e *FindingRecordError) Error() string {
	if e.stage == "" {
		return fmt.Sprintf("malformed finding record: %v", e.err)
	}
	return fmt.Sprintf("malformed finding record (%s): %v", e.stage, e.err)
}

func (e *FindingRecordError) Unwrap() error { return e.err }

// Stage returns the non-sensitive processing stage that rejected the record.
func (e *FindingRecordError) Stage() string { return e.stage }

// IngestFinding records one finding observation: it inserts an immutable
// occurrence row (with the preserved raw line) and upserts the deduplicated
// lifecycle entity. On a re-observation it advances last-seen and, if the finding
// had been Mitigated (absent from the target's previous scan) and is now back, it
// bumps times_mitigated — which drives the Resurfaced / Previously-Mitigated
// detection states. Analyst dispositions are left untouched (an accepted risk stays
// accepted until it expires). All writes run in one transaction.
func (s *Store) IngestFinding(ctx context.Context, scanID, targetID string, f types.NucleiFinding, raw []byte) error {
	// The record-local projection runs before any database work, so a malformed
	// record fails cleanly without touching the pool.
	prep, err := prepareOccurrence(f, raw)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var scanCreatedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT created_at FROM scans WHERE id = $1`, scanID).Scan(&scanCreatedAt); err != nil {
		return fmt.Errorf("read occurrence scan order: %w", err)
	}

	// The scan result is observed at ingest time; the scan-bundle import path
	// (internal/store/scanbundle.go) calls the same helper with the occurrence's
	// own timestamp instead, so reconstructed history keeps its original dates.
	if _, err := ingestFindingOccurrence(ctx, tx, scanID, targetID, scanCreatedAt, prep, time.Now()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// preparedOccurrence is the record-local projection of one occurrence, computed
// before any database work so malformed records fail cleanly (FindingRecordError).
type preparedOccurrence struct {
	key           string
	discriminator string
	rawProjection []byte
	rawLine       string
	f             types.NucleiFinding
	endpointKey   string
}

func prepareOccurrence(f types.NucleiFinding, raw []byte) (preparedOccurrence, error) {
	// DedupKey intentionally sees the parsed source fields before their database
	// projection: it drops C0 controls (including NUL) to retain the established
	// key semantics, while display columns render NUL visibly as "\0".
	rawProjection, err := findingJSONBProjection(raw)
	if err != nil {
		return preparedOccurrence{}, NewFindingRecordError("project raw finding JSON", err)
	}
	discriminator, err := resultDiscriminator(rawProjection)
	if err != nil {
		return preparedOccurrence{}, NewFindingRecordError("derive finding result identity", err)
	}
	return preparedOccurrence{
		key:           DedupKey(f.TemplateID, f.MatchedAt, discriminator),
		discriminator: discriminator,
		rawProjection: rawProjection,
		rawLine:       findingRawLine(raw),
		f:             findingTextProjection(f),
		endpointKey:   postgresText(types.EndpointKey(f.MatchedAt, f.Type)),
	}, nil
}

// ingestFindingOccurrence inserts one occurrence and upserts its lifecycle row
// inside the caller's transaction, using occurredAt as the observation time
// (what a normal ingest calls now()). It reports whether the lifecycle row was
// created by this occurrence.
func ingestFindingOccurrence(ctx context.Context, tx pgx.Tx, scanID, targetID string, scanCreatedAt time.Time,
	prep preparedOccurrence, occurredAt time.Time) (bool, error) {
	var occID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO findings
		   (scan_id, target_id, dedup_key, result_discriminator, template_id, name, severity,
		    host, matched_at, type, cve, tags, raw, raw_line, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 RETURNING id`,
		scanID, nullStr(targetID), prep.key, prep.discriminator, prep.f.TemplateID, prep.f.Info.Name, prep.f.Info.Severity,
		prep.f.Host, prep.f.MatchedAt, prep.f.Type, orEmpty(prep.f.CVEs()), orEmpty(prep.f.Info.Tags), prep.rawProjection, prep.rawLine, occurredAt,
	).Scan(&occID); err != nil {
		return false, fmt.Errorf("insert occurrence: %w", err)
	}

	var lcID int64
	var lcCreated bool
	// Scans can finish out of creation order. Lifecycle chronology follows the
	// stable (scan.created_at, scan.id) order, never ingest/finish order, so a
	// slower older scan cannot move last_seen backwards and manufacture a
	// mitigation cycle after a newer scan has already completed.
	const incomingNewer = `(finding_lifecycle.last_seen_scan IS NULL OR COALESCE((
		SELECT (current_scan.created_at, current_scan.id) < ($14::timestamptz, $16::uuid)
		  FROM scans current_scan
		 WHERE current_scan.id = finding_lifecycle.last_seen_scan
	), true))`
	const incomingOlder = `(finding_lifecycle.first_seen_scan IS NULL OR COALESCE((
		SELECT ($14::timestamptz, $16::uuid) < (current_scan.created_at, current_scan.id)
		  FROM scans current_scan
		 WHERE current_scan.id = finding_lifecycle.first_seen_scan
	), true))`
	const incomingAfterCovering = `COALESCE((
		SELECT (current_scan.created_at, current_scan.id) < ($14::timestamptz, $16::uuid)
		  FROM scans current_scan
		 WHERE current_scan.id = finding_lifecycle.last_covering_scan
	), true)`
	upsertLifecycle := fmt.Sprintf(
		`INSERT INTO finding_lifecycle
		   (dedup_key, result_discriminator, template_id, name, severity, host,
		    matched_at, endpoint_key, type, cve, tags, first_seen_scan, first_seen_at, last_seen_scan,
		    last_seen_at, latest_occurrence_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $15, $12, $15, $13)
		 ON CONFLICT (dedup_key) DO UPDATE SET
		    first_seen_scan      = CASE WHEN %[2]s THEN excluded.first_seen_scan ELSE finding_lifecycle.first_seen_scan END,
		    first_seen_at        = least(finding_lifecycle.first_seen_at, excluded.first_seen_at),
		    last_seen_scan       = CASE WHEN %[1]s THEN excluded.last_seen_scan ELSE finding_lifecycle.last_seen_scan END,
		    last_seen_at         = CASE WHEN %[1]s THEN $15 ELSE finding_lifecycle.last_seen_at END,
		    name                 = CASE WHEN %[1]s THEN excluded.name ELSE finding_lifecycle.name END,
		    severity             = CASE WHEN %[1]s THEN excluded.severity ELSE finding_lifecycle.severity END,
		    host                 = CASE WHEN %[1]s THEN excluded.host ELSE finding_lifecycle.host END,
		    matched_at           = CASE WHEN %[1]s THEN excluded.matched_at ELSE finding_lifecycle.matched_at END,
		    endpoint_key         = CASE WHEN %[1]s THEN excluded.endpoint_key ELSE finding_lifecycle.endpoint_key END,
		    type                 = CASE WHEN %[1]s THEN excluded.type ELSE finding_lifecycle.type END,
		    cve                  = CASE WHEN %[1]s THEN excluded.cve ELSE finding_lifecycle.cve END,
		    tags                 = CASE WHEN %[1]s THEN excluded.tags ELSE finding_lifecycle.tags END,
		    latest_occurrence_id = CASE WHEN %[1]s THEN excluded.latest_occurrence_id ELSE finding_lifecycle.latest_occurrence_id END,
		    times_mitigated      = finding_lifecycle.times_mitigated + CASE
		        WHEN %[1]s
		         AND %[3]s
		         AND finding_lifecycle.last_covering_scan IS NOT NULL
		         AND finding_lifecycle.last_seen_scan IS DISTINCT FROM finding_lifecycle.last_covering_scan
		         AND finding_lifecycle.last_seen_scan IS DISTINCT FROM excluded.last_seen_scan
		        THEN 1 ELSE 0 END
		 RETURNING id, (xmax = 0) AS created`,
		incomingNewer, incomingOlder, incomingAfterCovering)
	if err := tx.QueryRow(ctx, upsertLifecycle,
		prep.key, prep.discriminator, prep.f.TemplateID, prep.f.Info.Name, prep.f.Info.Severity, prep.f.Host, prep.f.MatchedAt,
		prep.endpointKey, prep.f.Type, orEmpty(prep.f.CVEs()), orEmpty(prep.f.Info.Tags), scanID, occID, scanCreatedAt,
		occurredAt, scanID,
	).Scan(&lcID, &lcCreated); err != nil {
		return false, fmt.Errorf("upsert lifecycle: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE findings SET finding_id = $1 WHERE id = $2`, lcID, occID); err != nil {
		return false, fmt.Errorf("link occurrence: %w", err)
	}
	return lcCreated, nil
}

// findingJSONBProjection makes a Nuclei result safe for PostgreSQL JSONB.
// encoding/json accepts \u0000 and decodes it to U+0000, while PostgreSQL rejects
// that code point in JSONB. The original JSONL bytes live in findings.raw_line;
// only this queryable projection replaces NUL with the printable "\0" spelling.
func findingJSONBProjection(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	return json.Marshal(sanitizeJSONNUL(value))
}

func sanitizeJSONNUL(value any) any {
	switch value := value.(type) {
	case string:
		return postgresText(value)
	case []any:
		for i := range value {
			value[i] = sanitizeJSONNUL(value[i])
		}
		return value
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, child := range value {
			out[postgresText(key)] = sanitizeJSONNUL(child)
		}
		return out
	default:
		return value
	}
}

// findingRawLine keeps valid Nuclei JSONL text unchanged while replacing invalid
// UTF-8 with U+FFFD so PostgreSQL TEXT cannot reject the occurrence. The
// byte-exact scanner stream remains available in the per-scan object archive.
func findingRawLine(raw []byte) string {
	return strings.ToValidUTF8(string(raw), "\uFFFD")
}

// findingTextProjection protects every indexed TEXT/TEXT[] field too. A NUL in
// one of these stable fields would otherwise fail before the safe JSONB
// projection is useful.
func findingTextProjection(f types.NucleiFinding) types.NucleiFinding {
	f.TemplateID = postgresText(f.TemplateID)
	f.Type = postgresText(f.Type)
	f.Host = postgresText(f.Host)
	f.MatchedAt = postgresText(f.MatchedAt)
	f.Info.Name = postgresText(f.Info.Name)
	f.Info.Severity = postgresText(f.Info.Severity)
	f.Info.Tags = postgresTexts(f.Info.Tags)
	if f.Info.Classification != nil {
		classification := *f.Info.Classification
		classification.CVEID = postgresTexts(classification.CVEID)
		classification.CWEID = postgresTexts(classification.CWEID)
		f.Info.Classification = &classification
	}
	return f
}

func postgresText(value string) string {
	return strings.ReplaceAll(value, "\x00", `\0`)
}

func postgresTexts(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = postgresText(value)
	}
	return out
}

// lifecycle read-time expressions. last_covering_scan is an evidence pointer
// advanced once when a scan completes, so lifecycle reads remain simple indexed
// row reads even when a scan contains thousands of concrete template ids.
const (
	// lcDetectionExpr derives the Tenable-style detection state purely from scan
	// observation across every target/scan associated with this global finding.
	lcDetectionExpr = `CASE
		WHEN l.last_covering_scan IS NULL THEN 'active'
		WHEN l.last_seen_scan IS DISTINCT FROM l.last_covering_scan
			THEN CASE WHEN l.times_mitigated >= 1 THEN 'previously_mitigated' ELSE 'mitigated' END
		WHEN l.first_seen_scan = l.last_covering_scan THEN 'new'
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
	lifecycleFrom = `FROM finding_lifecycle l`
)

// LifecycleRow is a deduplicated finding as returned to API callers (the triage
// view). DetectionState and EffectiveState are derived server-side from scan
// history + disposition; EffectiveSeverity honours a recast.
type LifecycleRow struct {
	ID                int64      `json:"id"`
	TargetIDs         []string   `json:"target_ids"`
	TemplateID        string     `json:"template_id"`
	Name              string     `json:"name"`
	Severity          string     `json:"severity"`
	RecastSeverity    *string    `json:"recast_severity,omitempty"`
	EffectiveSeverity string     `json:"effective_severity"`
	Host              string     `json:"host"`
	MatchedAt         string     `json:"matched_at"`
	Type              string     `json:"type"`
	CVE               []string   `json:"cve"`
	Tags              []string   `json:"tags"`
	Disposition       string     `json:"disposition"`
	AcceptExpiresAt   *time.Time `json:"accept_expires_at,omitempty"`
	DetectionState    string     `json:"detection_state"`
	EffectiveState    string     `json:"effective_state"`
	TimesMitigated    int        `json:"times_mitigated"`
	// AutoMitigationEligible is false when matched_at cannot be normalized to a
	// network host:port (for example file/code findings). Such rows deliberately
	// fail closed and require analyst disposition rather than inferred closure.
	AutoMitigationEligible bool      `json:"auto_mitigation_eligible"`
	FirstSeenScan          *string   `json:"first_seen_scan,omitempty"`
	LastSeenScan           *string   `json:"last_seen_scan,omitempty"`
	FirstSeenAt            time.Time `json:"first_seen_at"`
	LastSeenAt             time.Time `json:"last_seen_at"`
	LatestOccurrenceID     *int64    `json:"latest_occurrence_id,omitempty"`
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
	OccurrenceCount int             `json:"occurrence_count"`
	Raw             json.RawMessage `json:"raw,omitempty"`
}

// lcSelectCols is the projection shared by list + detail (up to the raw payload).
const lcSelectCols = `l.id,
	ARRAY(
	    SELECT DISTINCT occurrence.target_id::text
	      FROM findings occurrence
	     WHERE occurrence.finding_id = l.id AND occurrence.target_id IS NOT NULL
	     ORDER BY occurrence.target_id::text
	) AS target_ids,
	l.template_id, l.name, l.severity, l.recast_severity,
	` + effSevExpr + ` AS eff_sev, l.host, l.matched_at, l.type, l.cve, l.tags,
	l.disposition, l.accept_expires_at, ` + lcDetectionExpr + ` AS detection_state,
	` + lcEffectiveExpr + ` AS effective_state, l.times_mitigated,
	(l.endpoint_key <> '') AS auto_mitigation_eligible,
	l.first_seen_scan, l.last_seen_scan, l.first_seen_at, l.last_seen_at, l.latest_occurrence_id`

func scanLifecycleRow(row pgx.Row, r *LifecycleRow) error {
	return row.Scan(&r.ID, &r.TargetIDs, &r.TemplateID, &r.Name, &r.Severity, &r.RecastSeverity,
		&r.EffectiveSeverity, &r.Host, &r.MatchedAt, &r.Type, &r.CVE, &r.Tags,
		&r.Disposition, &r.AcceptExpiresAt, &r.DetectionState, &r.EffectiveState, &r.TimesMitigated,
		&r.AutoMitigationEligible,
		&r.FirstSeenScan, &r.LastSeenScan, &r.FirstSeenAt, &r.LastSeenAt, &r.LatestOccurrenceID)
}

// lcOrderBy is the shared sort: highest effective severity first, then most
// recently seen. Kept identical across list + export so an export matches the UI.
const lcOrderBy = ` ORDER BY ` + effSevOrder + ` DESC, l.last_seen_at DESC, l.id DESC`

// exportMaxRows caps an export so a pathological filter can't OOM the backend.
const exportMaxRows = 50000

// ListLifecycleFindings returns a page of deduplicated findings (severity-sorted,
// then most-recently-seen first) plus the total matching the filter.
func (s *Store) ListLifecycleFindings(ctx context.Context, q FindingQuery, limit, offset int) ([]LifecycleRow, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var args []any
	where, err := buildFindingWhere(q, &args)
	if err != nil {
		return nil, 0, err
	}

	var total int
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) "+lifecycleFrom+" "+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit)
	limitPH := len(args)
	args = append(args, offset)
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
// boolean reports whether the row cap omitted another finding; the filter's
// Limit/Offset are ignored.
func (s *Store) ExportLifecycleFindings(ctx context.Context, q FindingQuery) ([]LifecycleRow, bool, error) {
	var out []LifecycleRow
	rowCapped, err := s.StreamLifecycleFindings(ctx, q, func(row LifecycleRow) error {
		out = append(out, row)
		return nil
	})
	return out, rowCapped, err
}

// StreamLifecycleFindings visits matching lifecycle rows in database order. The
// callback runs while each row is held by the pgx cursor, so callers can encode
// or otherwise consume a row without retaining the full export in memory. The
// boolean reports whether a row beyond exportMaxRows was available; callers can
// surface that row cap as an explicit incomplete export rather than confusing it
// with a complete result set.
func (s *Store) StreamLifecycleFindings(ctx context.Context, q FindingQuery, fn func(LifecycleRow) error) (bool, error) {
	var args []any
	where, err := buildFindingWhere(q, &args)
	if err != nil {
		return false, err
	}
	// Fetch one probe row beyond the delivered cap so the caller can distinguish
	// "exactly capped" from "there were more matching findings".
	args = append(args, exportMaxRows+1)
	limitPH := len(args)
	query := fmt.Sprintf(`SELECT %s %s %s%s LIMIT $%d`,
		lcSelectCols, lifecycleFrom, where, lcOrderBy, limitPH)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return false, err
	}
	// A byte cap stops the callback, but closing the pgx rows still releases the
	// database portal/connection; this is cleanup, not an early query cancel.
	defer rows.Close()

	seen := 0
	for rows.Next() {
		if seen == exportMaxRows {
			return true, nil
		}
		var r LifecycleRow
		if err := scanLifecycleRow(rows, &r); err != nil {
			return false, err
		}
		if err := fn(r); err != nil {
			return false, err
		}
		seen++
	}
	return false, rows.Err()
}

// RawExportRow pairs a lifecycle finding's id with the preserved Nuclei JSON of
// its latest occurrence, so a raw JSONL export stays joinable to the projected
// (JSON/CSV/SARIF) exports on that id.
type RawExportRow struct {
	ID  int64
	Raw json.RawMessage
}

// ExportLifecycleRaw returns each matching finding's lifecycle id + the preserved
// Nuclei JSON of its latest occurrence (same filter + order as the list), for a
// raw JSONL export. The first boolean reports whether the row cap omitted another
// lifecycle row; the count reports lifecycle rows whose latest occurrence was
// unavailable. Such rows are intentionally omitted from raw JSONL.
func (s *Store) ExportLifecycleRaw(ctx context.Context, q FindingQuery) ([]RawExportRow, bool, int64, error) {
	var out []RawExportRow
	rowCapped, missing, err := s.StreamLifecycleRaw(ctx, q, func(row RawExportRow) error {
		out = append(out, row)
		return nil
	})
	return out, rowCapped, missing, err
}

// StreamLifecycleRaw visits matching findings' lifecycle id and preserved raw
// occurrence payload in database order. The callback runs one row at a time so
// raw request/response bodies do not accumulate in a process-sized slice. The
// first result reports whether a lifecycle row beyond exportMaxRows was
// available; the count reports lifecycle rows encountered without a live latest
// occurrence. Such rows are omitted from the callback output.
func (s *Store) StreamLifecycleRaw(ctx context.Context, q FindingQuery, fn func(RawExportRow) error) (bool, int64, error) {
	var args []any
	where, err := buildFindingWhere(q, &args)
	if err != nil {
		return false, 0, err
	}
	args = append(args, exportMaxRows+1)
	limitPH := len(args)
	query := fmt.Sprintf(`SELECT l.id, (o.id IS NULL), COALESCE(o.raw_line, o.raw::text) %s LEFT JOIN findings o ON o.id = l.latest_occurrence_id %s%s LIMIT $%d`,
		lifecycleFrom, where, lcOrderBy, limitPH)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return false, 0, err
	}
	// A byte cap stops the callback, but closing the pgx rows still releases the
	// database portal/connection; this is cleanup, not an early query cancel.
	defer rows.Close()

	seen := 0
	var missing int64
	for rows.Next() {
		if seen == exportMaxRows {
			return true, missing, nil
		}
		var r RawExportRow
		var missingOccurrence bool
		var raw *string
		if err := rows.Scan(&r.ID, &missingOccurrence, &raw); err != nil {
			return false, missing, err
		}
		seen++
		if missingOccurrence || raw == nil {
			missing++
			continue
		}
		r.Raw = json.RawMessage(*raw)
		if err := fn(r); err != nil {
			return false, missing, err
		}
	}
	return false, missing, rows.Err()
}

// GetLifecycleFinding returns one deduplicated finding by id, including the
// disposition/recast audit trail and the raw JSON of its latest occurrence.
func (s *Store) GetLifecycleFinding(ctx context.Context, id int64) (LifecycleDetail, error) {
	var d LifecycleDetail
	var dNote, dBy, rNote, rBy, rawLine *string
	query := fmt.Sprintf(
		`SELECT %s, l.disposition_note, l.disposition_by, l.disposition_at,
		        l.recast_note, l.recast_by, l.recast_at,
		        (SELECT count(*) FROM findings occurrence WHERE occurrence.finding_id = l.id),
		        COALESCE(o.raw_line, o.raw::text)
		 %s
		 LEFT JOIN findings o ON o.id = l.latest_occurrence_id
		 WHERE l.id = $1`,
		lcSelectCols, lifecycleFrom)
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&d.ID, &d.TargetIDs, &d.TemplateID, &d.Name, &d.Severity, &d.RecastSeverity,
		&d.EffectiveSeverity, &d.Host, &d.MatchedAt, &d.Type, &d.CVE, &d.Tags,
		&d.Disposition, &d.AcceptExpiresAt, &d.DetectionState, &d.EffectiveState, &d.TimesMitigated,
		&d.AutoMitigationEligible,
		&d.FirstSeenScan, &d.LastSeenScan, &d.FirstSeenAt, &d.LastSeenAt, &d.LatestOccurrenceID,
		&dNote, &dBy, &d.DispositionAt, &rNote, &rBy, &d.RecastAt,
		&d.OccurrenceCount, &rawLine)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LifecycleDetail{}, ErrNotFound
		}
		return LifecycleDetail{}, err
	}
	d.DispositionNote, d.DispositionBy = deref(dNote), deref(dBy)
	d.RecastNote, d.RecastBy = deref(rNote), deref(rBy)
	if rawLine != nil {
		d.Raw = json.RawMessage(*rawLine)
	}
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
