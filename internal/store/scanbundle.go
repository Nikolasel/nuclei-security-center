package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Scan bundle import/export (#136). Export reads the complete record of one scan
// (scan row + dispatch spec + occurrence log) into structs the backend assembles
// into the versioned manifest; import recreates the scan on this instance and
// ingests its findings through the normal lifecycle path, so the destination
// derives its own dedup/lifecycle state from the results exactly as
// if it had scanned the target itself. External endpoint-coverage claims are not
// trusted as local evidence; imported occurrences can still provide positive
// evidence through the normal lifecycle path. Missing referenced entities fall
// back to their default (NULL) value. Imported endpoint coverage is ignored by
// default; an operator may explicitly opt into trusting it for mitigation.

// BundleFinding is one immutable occurrence plus the preserved Nuclei JSON
// (`COALESCE(raw_line, raw::text)`), ready for the manifest.
type BundleFinding struct {
	ID         int64           `json:"id"`
	TargetID   string          `json:"target_id,omitempty"`
	TemplateID string          `json:"template_id"`
	Name       string          `json:"name,omitempty"`
	Severity   string          `json:"severity,omitempty"`
	Host       string          `json:"host,omitempty"`
	MatchedAt  string          `json:"matched_at,omitempty"`
	Type       string          `json:"type,omitempty"`
	CVE        []string        `json:"cve,omitempty"`
	Tags       []string        `json:"tags,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// ScanExportBundle is the exporter's view of one scan: the scan row (including
// the reference ids and the verbatim dispatch spec) plus its findings.
type ScanExportBundle struct {
	ID                  string
	State               string
	Source              string
	TargetID            string
	TemplateSetID       string
	ScanPolicyID        string
	NodeID              string
	ScheduleID          string
	NucleiVersion       string
	TemplatesCommit     string
	Error               string
	SkippedFindingCount int
	CreatedAt           time.Time
	StartedAt           *time.Time
	FinishedAt          *time.Time
	DiscoveredTargets   []string
	CoveredEndpoints    []types.EndpointCoverage
	CoverageWarning     string
	Spec                json.RawMessage
	Findings            []BundleFinding
}

func scanExportBundleRow(row pgx.Row) (*ScanExportBundle, error) {
	var e ScanExportBundle
	var targetID, templateSetID, scanPolicyID, nodeID, scheduleID, nucleiVersion, templatesCommit, errStr, coverageWarning *string
	var coveredJSON []byte
	if err := row.Scan(&e.ID, &e.State, &e.Source,
		&targetID, &templateSetID, &scanPolicyID, &nodeID, &scheduleID,
		&nucleiVersion, &templatesCommit, &errStr, &e.SkippedFindingCount,
		&e.CreatedAt, &e.StartedAt, &e.FinishedAt,
		&e.DiscoveredTargets, &coveredJSON, &coverageWarning, &e.Spec); err != nil {
		return nil, err
	}
	e.TargetID = deref(targetID)
	e.TemplateSetID = deref(templateSetID)
	e.ScanPolicyID = deref(scanPolicyID)
	e.NodeID = deref(nodeID)
	e.ScheduleID = deref(scheduleID)
	e.NucleiVersion = deref(nucleiVersion)
	e.TemplatesCommit = deref(templatesCommit)
	e.Error = deref(errStr)
	e.CoverageWarning = deref(coverageWarning)
	if len(coveredJSON) > 0 {
		if err := json.Unmarshal(coveredJSON, &e.CoveredEndpoints); err != nil {
			return nil, fmt.Errorf("decode endpoint coverage: %w", err)
		}
	}
	if len(e.Spec) == 0 {
		e.Spec = json.RawMessage(`{}`)
	}
	return &e, nil
}

// ExportScanBundle reads everything a bundle for one scan needs — the scan row
// and its occurrences (with preserved raw JSON). It returns ErrNotFound when
// the scan is unknown.
func (s *Store) ExportScanBundle(ctx context.Context, scanID string) (*ScanExportBundle, error) {
	scan, err := scanExportBundleRow(s.pool.QueryRow(ctx,
		`SELECT id, state, source, target_id, template_set_id, scan_policy_id, node_id, schedule_id,
		        nuclei_version, templates_commit, error, skipped_finding_count,
		        created_at, started_at, finished_at,
		        discovered_targets, covered_endpoints, coverage_warning, spec
		   FROM scans WHERE id = $1`, scanID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	findingRows, err := s.pool.Query(ctx,
		`SELECT id, COALESCE(target_id::text, ''), template_id, name, severity, host, matched_at,
		        type, cve, tags, created_at,
		        COALESCE(raw_line, raw::text)
		   FROM findings
		  WHERE scan_id = $1
		  ORDER BY created_at, id`, scanID)
	if err != nil {
		return nil, err
	}
	defer findingRows.Close()
	for findingRows.Next() {
		var f BundleFinding
		var raw string
		if err := findingRows.Scan(&f.ID, &f.TargetID, &f.TemplateID, &f.Name, &f.Severity, &f.Host,
			&f.MatchedAt, &f.Type, &f.CVE, &f.Tags, &f.CreatedAt, &raw); err != nil {
			return nil, err
		}
		f.Raw = json.RawMessage(raw)
		scan.Findings = append(scan.Findings, f)
	}
	return scan, findingRows.Err()
}

// ScanBundleForExport assembles the versioned manifest for one scan result: the
// scan record, its occurrence log, and the resolved config snapshots (target /
// template set / scan policy) so the bundle is understandable standalone. It
// returns ErrNotFound when the scan is unknown.
func (s *Store) ScanBundleForExport(ctx context.Context, scanID string) (*types.ScanBundle, error) {
	export, err := s.ExportScanBundle(ctx, scanID)
	if err != nil {
		return nil, err
	}

	var templateIDs []string
	var spec types.ScanSpec
	if len(export.Spec) > 0 {
		if err := json.Unmarshal(export.Spec, &spec); err == nil {
			templateIDs = spec.Templates.TemplateIDs
		}
	}

	cfg := types.ScanBundleConfig{
		TargetID:      export.TargetID,
		TemplateSetID: export.TemplateSetID,
		ScanPolicyID:  export.ScanPolicyID,
		NodeID:        export.NodeID,
		ScheduleID:    export.ScheduleID,
	}
	if export.TargetID != "" {
		if t, err := s.GetTarget(ctx, export.TargetID); err == nil {
			cfg.Target = &types.TargetBundleSnapshot{Name: t.Name, Hosts: t.Hosts, Tags: t.Tags}
		} else if !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("read target snapshot: %w", err)
		}
	}
	if export.TemplateSetID != "" {
		if ts, err := s.GetTemplateSet(ctx, export.TemplateSetID); err == nil {
			cfg.TemplateSet = &types.TemplateSetBundleSnapshot{Name: ts.Name, Mode: string(ts.Mode)}
		} else if !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("read template set snapshot: %w", err)
		}
	}
	if export.ScanPolicyID != "" {
		if p, err := s.GetScanPolicy(ctx, export.ScanPolicyID); err == nil {
			cfg.ScanPolicy = &types.ScanPolicyBundleSnapshot{
				Name: p.Name, TemplateSetID: p.TemplateSetID,
				RateLimit: p.RateLimit, Concurrency: p.Concurrency, TimeoutSec: p.TimeoutSec, MaxHostError: p.MaxHostError,
				DiscoveryEnabled: p.DiscoveryEnabled, DiscoveryHostDiscovery: p.DiscoveryHostDiscovery,
				DiscoveryScanType: p.DiscoveryScanType, DiscoveryPorts: p.DiscoveryPorts,
				DiscoveryTimeoutSec: p.DiscoveryTimeoutSec, DiscoveryRate: p.DiscoveryRate,
				DiscoveryProbeTimeoutMs: p.DiscoveryProbeTimeoutMs, DiscoveryRetries: p.DiscoveryRetries,
			}
		} else if !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("read scan policy snapshot: %w", err)
		}
	}

	findings := make([]types.ScanBundleFinding, 0, len(export.Findings))
	for _, f := range export.Findings {
		findings = append(findings, types.ScanBundleFinding{
			ID: f.ID, TargetID: f.TargetID, TemplateID: f.TemplateID, Name: f.Name,
			Severity: f.Severity, Host: f.Host, MatchedAt: f.MatchedAt, Type: f.Type,
			CVE: f.CVE, Tags: f.Tags, CreatedAt: f.CreatedAt, Raw: f.Raw,
		})
	}

	return &types.ScanBundle{
		Format:        types.ScanBundleFormat,
		FormatVersion: types.ScanBundleFormatVersion,
		ExportedAt:    time.Now().UTC(),
		Config:        cfg,
		Scan: types.ScanBundleScan{
			ID: export.ID, State: export.State, Source: export.Source,
			NucleiVersion: export.NucleiVersion, TemplatesCommit: export.TemplatesCommit,
			Error: export.Error, SkippedFindingCount: export.SkippedFindingCount,
			CreatedAt: export.CreatedAt, StartedAt: export.StartedAt, FinishedAt: export.FinishedAt,
			DiscoveredTargets: export.DiscoveredTargets, CoveredEndpoints: export.CoveredEndpoints,
			CoverageWarning: export.CoverageWarning, TemplateIDs: templateIDs, Spec: export.Spec,
		},
		Findings: findings,
	}, nil
}

// ImportConflict is how import handles a scan id that already exists locally.
type ImportConflict string

const (
	// ImportConflictError refuses to import over an existing scan (409). It is
	// the default: importing must never silently clobber local data.
	ImportConflictError ImportConflict = "error"
	// ImportConflictDuplicate imports under a freshly minted id instead, keeping
	// the exported scan intact locally while duplicating it under a new id.
	ImportConflictDuplicate ImportConflict = "duplicate"
)

// ImportCoverageMode controls whether endpoint coverage from the exporting
// scanner may be used as mitigation evidence on import.
type ImportCoverageMode string

const (
	// ImportCoverageIgnore is the safe default: imported coverage is discarded.
	ImportCoverageIgnore ImportCoverageMode = "ignore"
	// ImportCoverageTrust is an explicit operator opt-in to use exact imported
	// endpoint coverage as mitigation evidence.
	ImportCoverageTrust ImportCoverageMode = "trust"
)

// CoverageOrigin identifies the provenance of persisted endpoint coverage.
// Only node traces and explicit trusted imports may contribute claimed
// mitigation evidence; ordinary imports are retained as untrusted provenance.
const (
	CoverageOriginNode            = "node"
	CoverageOriginImportUntrusted = "import_untrusted"
	CoverageOriginImportTrusted   = "import_trusted"
	coverageOriginClaimedSQL      = "('" + CoverageOriginNode + "', '" + CoverageOriginImportTrusted + "')"
)

func coverageOriginAllowsClaimedCoverage(origin string) bool {
	return origin == CoverageOriginNode || origin == CoverageOriginImportTrusted
}

// ErrInvalidImportedCoverage indicates a malformed coverage claim supplied to
// the explicit trust mode. The default ignore mode deliberately does not reject
// these exporter-authored claims because it never consumes them.
var ErrInvalidImportedCoverage = errors.New("invalid imported endpoint coverage")

func validateImportedCoverage(endpoints []types.EndpointCoverage) error {
	for i, endpoint := range endpoints {
		if strings.TrimSpace(endpoint.TemplateID) == "" || strings.TrimSpace(endpoint.Endpoint) == "" {
			return fmt.Errorf("%w at index %d", ErrInvalidImportedCoverage, i)
		}
	}
	return nil
}

// ImportFallback records one bundle reference that did not exist locally and
// fell back to its default (NULL).
type ImportFallback struct {
	Field      string `json:"field"`
	ExporterID string `json:"exporter_id"`
}

// ScanImportResult summarizes an applied import.
type ScanImportResult struct {
	ScanID           string             `json:"scan_id"`
	FindingsImported int                `json:"findings_imported"`
	LifecycleCreated int                `json:"lifecycle_created"`
	LifecycleUpdated int                `json:"lifecycle_updated"`
	CoverageMode     ImportCoverageMode `json:"coverage_mode"`
	Fallbacks        []ImportFallback   `json:"fallbacks,omitempty"`
}

// ErrScanBundleConflict is returned when importing a bundle whose scan id
// already exists locally under the default (error) conflict policy.
var ErrScanBundleConflict = errors.New("scan already exists")

// ImportScanBundle recreates a scan and ingests its findings on this instance
// through the normal lifecycle path, so the destination derives its own
// dedup/lifecycle state from the results exactly as if it had scanned the
// target itself. It runs in one transaction, so a malformed bundle leaves no
// partial state. Referenced entities missing locally fall back to NULL — the
// same default a deleted target/policy leaves behind.
// Imported endpoint coverage is discarded unless coverageMode is the explicit
// operator opt-in ImportCoverageTrust.
//
// The manifest is validated by the caller (types.ScanBundle.Validate); this
// function still fails closed on any per-row projection error.
func (s *Store) ImportScanBundle(ctx context.Context, b *types.ScanBundle, conflict ImportConflict, coverageMode ImportCoverageMode) (*ScanImportResult, error) {
	if coverageMode == "" {
		coverageMode = ImportCoverageIgnore
	}
	if coverageMode != ImportCoverageIgnore && coverageMode != ImportCoverageTrust {
		return nil, fmt.Errorf("invalid import coverage mode %q", coverageMode)
	}
	if coverageMode == ImportCoverageTrust {
		if err := validateImportedCoverage(b.Scan.CoveredEndpoints); err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	scanID := b.Scan.ID
	if conflict == ImportConflictDuplicate {
		scanID = types.NewID()
	} else {
		var exists bool
		err := tx.QueryRow(ctx, `SELECT true FROM scans WHERE id = $1`, scanID).Scan(&exists)
		if err == nil {
			return nil, ErrScanBundleConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}

	if !json.Valid(b.Scan.Spec) {
		return nil, fmt.Errorf("scan bundle: scan.spec is not valid JSON")
	}

	// Missing referenced entities fall back to NULL; the import must not assume
	// they exist locally (they may have been deleted since export, or never have
	// existed on this instance).
	scan, fallbacks, err := resolveScanBundleRefs(ctx, tx, b)
	if err != nil {
		return nil, err
	}

	state := b.Scan.State
	errText := b.Scan.Error
	if state == string(types.ScanQueued) || state == string(types.ScanRunning) {
		// A bundle taken from a scan that was still in flight. Recreating it as
		// queued/running would strand a scan nothing will ever drive (imports are
		// historical records, never dispatched); record it as a terminal failure.
		state = string(types.ScanFailed)
		errText = firstNonEmpty(errText, "scan was in-flight when exported; imported as failed")
	}

	coverageOrigin := CoverageOriginImportUntrusted
	if coverageMode == ImportCoverageTrust {
		coverageOrigin = CoverageOriginImportTrusted
	}

	// `covered_endpoints` is execution-trace evidence used for mitigation, and
	// `coverage_warning` describes that trace. Both are claims from the exporting
	// scanner node and untrusted on import by default, so never persist either
	// unless the operator explicitly selected ImportCoverageTrust. In trust mode,
	// exact pairs are persisted and applied using the same lifecycle evidence rules
	// as a completed local scan. `discovered_targets` is also external scanner
	// output, but is retained as display-only provenance; no lifecycle path uses it
	// as evidence. Imported occurrences still provide positive evidence through the
	// normal ingest path below.
	var coveredJSON []byte
	var coverageWarning *string
	if coverageMode == ImportCoverageTrust && b.Scan.CoveredEndpoints != nil {
		coveredJSON, err = json.Marshal(b.Scan.CoveredEndpoints)
		if err != nil {
			return nil, fmt.Errorf("marshal imported endpoint coverage: %w", err)
		}
		coverageWarning = nullStr(b.Scan.CoverageWarning)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO scans (id, state, spec, target_id, template_set_id, scan_policy_id,
		                    source, schedule_id, node_id, nuclei_version, templates_commit, error,
		                    skipped_finding_count, created_at, started_at, finished_at,
		                    discovered_targets, covered_endpoints, coverage_warning, coverage_origin)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
		scanID, state, b.Scan.Spec, nullStr(scan.TargetID), nullStr(scan.TemplateSetID), nullStr(scan.ScanPolicyID),
		nullStr(b.Scan.Source), nullStr(scan.ScheduleID), nullStr(scan.NodeID), nullStr(b.Scan.NucleiVersion), nullStr(b.Scan.TemplatesCommit), nullStr(errText),
		b.Scan.SkippedFindingCount, b.Scan.CreatedAt, b.Scan.StartedAt, b.Scan.FinishedAt,
		orEmpty(b.Scan.DiscoveredTargets), coveredJSON, coverageWarning, coverageOrigin,
	); err != nil {
		// Two concurrent imports of the same bundle can both clear the existence
		// pre-check under READ COMMITTED; surface the unique-violation loser as
		// the intended 409 instead of a 500.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrScanBundleConflict
		}
		return nil, fmt.Errorf("insert imported scan: %w", err)
	}

	// Ingest each occurrence like a normally completed scan: the dedup identity
	// is recomputed from the verbatim raw payload and the existing lifecycle
	// path derives the destination's own first/last-seen, mitigation counters,
	// and evidence pointers. Analyst overlays already on the destination are
	// never touched (import is the scan result, not the exporter's analysis).
	result := &ScanImportResult{ScanID: scanID, CoverageMode: coverageMode, Fallbacks: fallbacks}
	for _, bf := range b.Findings {
		f := types.NucleiFinding{
			TemplateID: bf.TemplateID,
			Type:       bf.Type,
			Host:       bf.Host,
			MatchedAt:  bf.MatchedAt,
			Info: types.NucleiInfo{
				Name:     bf.Name,
				Severity: bf.Severity,
				Tags:     orEmpty(bf.Tags),
			},
		}
		if len(bf.CVE) > 0 {
			f.Info.Classification = &types.NucleiClassification{CVEID: bf.CVE}
		}
		prep, prepErr := prepareOccurrence(f, bf.Raw)
		if prepErr != nil {
			return nil, fmt.Errorf("scan bundle: prepare finding %q/%q: %w", bf.TemplateID, bf.MatchedAt, prepErr)
		}
		created, err := ingestFindingOccurrence(ctx, tx, scanID, scan.TargetID, b.Scan.CreatedAt, prep, bf.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan bundle: ingest finding %q/%q: %w", bf.TemplateID, bf.MatchedAt, err)
		}
		if created {
			result.LifecycleCreated++
		} else {
			result.LifecycleUpdated++
		}
		result.FindingsImported++
	}

	// A completed import advances last_covering_scan only for lifecycle rows the
	// bundle actually observed, unless the operator explicitly trusted exact
	// imported endpoint coverage. Failed/cancelled imports prove nothing.
	if state == string(types.ScanComplete) {
		if err := applyScanCoverage(ctx, tx, scanID, coverageMode == ImportCoverageTrust); err != nil {
			return nil, fmt.Errorf("apply imported scan coverage: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// resolvedScanRefs is the import-time resolution of the bundle's config
// references against the destination.
type resolvedScanRefs struct {
	TargetID      string
	TemplateSetID string
	ScanPolicyID  string
	NodeID        string
	ScheduleID    string
}

// resolveScanBundleRefs resolves each referenced entity id against the
// destination inside the import transaction. A reference that does not exist
// falls back to NULL and is reported in the returned fallback list.
func resolveScanBundleRefs(ctx context.Context, tx pgx.Tx, b *types.ScanBundle) (resolvedScanRefs, []ImportFallback, error) {
	var out resolvedScanRefs
	var fallbacks []ImportFallback
	type ref struct {
		field    string
		table    string
		id       string
		fallback *string
	}
	refs := []ref{
		{field: "target_id", table: "targets", id: b.Config.TargetID, fallback: &out.TargetID},
		{field: "template_set_id", table: "template_sets", id: b.Config.TemplateSetID, fallback: &out.TemplateSetID},
		{field: "scan_policy_id", table: "scan_policies", id: b.Config.ScanPolicyID, fallback: &out.ScanPolicyID},
		{field: "node_id", table: "scanner_nodes", id: b.Config.NodeID, fallback: &out.NodeID},
		{field: "schedule_id", table: "schedules", id: b.Config.ScheduleID, fallback: &out.ScheduleID},
	}
	for _, r := range refs {
		if r.id == "" {
			continue
		}
		var exists bool
		err := tx.QueryRow(ctx, `SELECT true FROM `+r.table+` WHERE id = $1`, r.id).Scan(&exists)
		switch {
		case err == nil:
			*r.fallback = r.id
		case errors.Is(err, pgx.ErrNoRows):
			fallbacks = append(fallbacks, ImportFallback{Field: r.field, ExporterID: r.id})
		default:
			return out, nil, err
		}
	}
	return out, fallbacks, nil
}

// applyScanCoverage advances the destination's last_covering_scan evidence
// pointers for lifecycle rows the imported scan actually observed. When
// trustClaimedCoverage is true, exact persisted endpoint pairs are also
// eligible, matching MarkComplete's local-scan evidence rules. The caller gates
// this on state == ScanComplete, so a failed import proves nothing.
func applyScanCoverage(ctx context.Context, tx pgx.Tx, scanID string, trustClaimedCoverage bool) error {
	candidates := `
		 observed AS MATERIALIZED (
		    SELECT DISTINCT observed.finding_id
		      FROM completed_scan
		      JOIN findings observed ON observed.scan_id = completed_scan.id
		     WHERE observed.finding_id IS NOT NULL
		 ),
		 candidate_lifecycle AS MATERIALIZED (
		    SELECT observed.finding_id AS id FROM observed
		 )`
	if trustClaimedCoverage {
		candidates = fmt.Sprintf(`
		 coverage_pairs AS MATERIALIZED (
		    SELECT pair->>'template_id' AS template_id,
		           pair->>'endpoint' AS endpoint
		      FROM completed_scan
		      CROSS JOIN LATERAL jsonb_array_elements(
		          CASE WHEN completed_scan.coverage_origin IN %s
		                      AND completed_scan.skipped_finding_count = 0
		               THEN COALESCE(completed_scan.covered_endpoints, '[]'::jsonb)
		               ELSE '[]'::jsonb END
		      ) AS pair
		     WHERE jsonb_typeof(pair) = 'object'
		 ),
		 observed AS MATERIALIZED (
		    SELECT DISTINCT observed.finding_id
		      FROM completed_scan
		      JOIN findings observed ON observed.scan_id = completed_scan.id
		     WHERE observed.finding_id IS NOT NULL
		 ),
		 candidate_lifecycle AS MATERIALIZED (
		    SELECT lifecycle.id
		      FROM coverage_pairs coverage
		      JOIN finding_lifecycle lifecycle
		        ON lifecycle.template_id = coverage.template_id
		       AND lifecycle.endpoint_key = coverage.endpoint
		     WHERE lifecycle.endpoint_key <> ''
		    UNION
		    SELECT observed.finding_id FROM observed
		 )`, coverageOriginClaimedSQL)
	}
	query := fmt.Sprintf(`WITH completed_scan AS (
		    SELECT id, target_id, covered_endpoints, coverage_origin, skipped_finding_count, created_at
		      FROM scans WHERE id = $1
		 ),%s
		 UPDATE finding_lifecycle lifecycle
		    SET last_covering_scan = completed_scan.id
		   FROM completed_scan, candidate_lifecycle candidate
		  WHERE lifecycle.id = candidate.id
		    AND EXISTS (
		        SELECT 1
		          FROM findings associated
		          JOIN scans associated_scan ON associated_scan.id = associated.scan_id
		         WHERE associated.finding_id = lifecycle.id
		           AND associated_scan.target_id IS NOT DISTINCT FROM completed_scan.target_id
		    )
		    AND (
		        lifecycle.last_covering_scan IS NULL
		        OR EXISTS (
		            SELECT 1
		              FROM scans previous
		             WHERE previous.id = lifecycle.last_covering_scan
		               AND (previous.created_at, previous.id) <
		                   (completed_scan.created_at, completed_scan.id)
		        )
		    )`, candidates)
	_, err := tx.Exec(ctx, query, scanID)
	return err
}

// firstNonEmpty returns the first non-empty value, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
