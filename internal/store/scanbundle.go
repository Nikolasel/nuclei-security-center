package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Scan bundle import/export (#136). Export reads the complete record of one scan
// (scan row + dispatch spec + occurrence log + the lifecycle rows for the scan's
// findings) into structs the backend assembles into the versioned manifest;
// import recreates the scan and its findings on this instance and merges the
// destination finding lifecycle from the bundle, with missing referenced
// entities falling back to their default (NULL) value.

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

// BundleLifecycle is the full lifecycle state of one global finding observed by
// the exported scan, so the destination updates its lifecycle from the bundle
// rather than only re-inserting occurrences.
type BundleLifecycle struct {
	DedupKey            string     `json:"dedup_key,omitempty"`
	ResultDiscriminator string     `json:"result_discriminator,omitempty"`
	TemplateID          string     `json:"template_id"`
	Name                string     `json:"name,omitempty"`
	Severity            string     `json:"severity,omitempty"`
	Host                string     `json:"host,omitempty"`
	MatchedAt           string     `json:"matched_at,omitempty"`
	Type                string     `json:"type,omitempty"`
	CVE                 []string   `json:"cve,omitempty"`
	Tags                []string   `json:"tags,omitempty"`
	EndpointKey         string     `json:"endpoint_key,omitempty"`
	FirstSeenAt         time.Time  `json:"first_seen_at"`
	LastSeenAt          time.Time  `json:"last_seen_at"`
	TimesMitigated      int        `json:"times_mitigated"`
	Disposition         string     `json:"disposition"`
	AcceptExpiresAt     *time.Time `json:"accept_expires_at,omitempty"`
	DispositionNote     string     `json:"disposition_note,omitempty"`
	DispositionBy       string     `json:"disposition_by,omitempty"`
	DispositionAt       *time.Time `json:"disposition_at,omitempty"`
	RecastSeverity      string     `json:"recast_severity,omitempty"`
	RecastNote          string     `json:"recast_note,omitempty"`
	RecastBy            string     `json:"recast_by,omitempty"`
	RecastAt            *time.Time `json:"recast_at,omitempty"`
}

// ScanExportBundle is the exporter's view of one scan: the scan row (including
// the reference ids and the verbatim dispatch spec) plus its findings and the
// lifecycle rows for those findings.
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
	Lifecycle           []BundleLifecycle
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

// ExportScanBundle reads everything a bundle for one scan needs — the scan row,
// its occurrences (with preserved raw JSON), and the lifecycle rows for those
// occurrences. It returns ErrNotFound when the scan is unknown.
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
	if err := findingRows.Err(); err != nil {
		return nil, err
	}
	findingRows.Close()

	lifecycleRows, err := s.pool.Query(ctx,
		`SELECT DISTINCT l.id, l.dedup_key, l.result_discriminator, l.template_id, l.name, l.severity, l.host,
		        l.matched_at, l.type, l.cve, l.tags, l.endpoint_key,
		        l.first_seen_at, l.last_seen_at, l.times_mitigated,
		        l.disposition, l.accept_expires_at, l.disposition_note, l.disposition_by, l.disposition_at,
		        l.recast_severity, l.recast_note, l.recast_by, l.recast_at
		   FROM finding_lifecycle l
		   JOIN findings f ON f.finding_id = l.id
		  WHERE f.scan_id = $1
		  ORDER BY l.id`, scanID)
	if err != nil {
		return nil, err
	}
	defer lifecycleRows.Close()
	for lifecycleRows.Next() {
		var l BundleLifecycle
		var lcID int64
		var dispositionNote, dispositionBy, recastSeverity, recastNote, recastBy *string
		if err := lifecycleRows.Scan(&lcID, &l.DedupKey, &l.ResultDiscriminator, &l.TemplateID, &l.Name, &l.Severity,
			&l.Host, &l.MatchedAt, &l.Type, &l.CVE, &l.Tags, &l.EndpointKey,
			&l.FirstSeenAt, &l.LastSeenAt, &l.TimesMitigated,
			&l.Disposition, &l.AcceptExpiresAt, &dispositionNote, &dispositionBy, &l.DispositionAt,
			&recastSeverity, &recastNote, &recastBy, &l.RecastAt); err != nil {
			return nil, err
		}
		l.DispositionNote = deref(dispositionNote)
		l.DispositionBy = deref(dispositionBy)
		l.RecastSeverity = deref(recastSeverity)
		l.RecastNote = deref(recastNote)
		l.RecastBy = deref(recastBy)
		scan.Lifecycle = append(scan.Lifecycle, l)
	}
	return scan, lifecycleRows.Err()
}

// ScanBundleForExport assembles the versioned manifest for one scan: the scan
// record, its occurrence log, the lifecycle rows for its findings, and the
// resolved config snapshots (target / template set / scan policy) so the bundle
// is understandable standalone. It returns ErrNotFound when the scan is unknown.
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
				DiscoveryEnabled: p.DiscoveryEnabled, DiscoveryScanType: p.DiscoveryScanType, DiscoveryPorts: p.DiscoveryPorts,
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
	lifecycle := make([]types.ScanBundleLifecycle, 0, len(export.Lifecycle))
	for _, l := range export.Lifecycle {
		lifecycle = append(lifecycle, types.ScanBundleLifecycle{
			DedupKey: l.DedupKey, TemplateID: l.TemplateID, MatchedAt: l.MatchedAt,
			ResultDiscriminator: l.ResultDiscriminator, Name: l.Name, Severity: l.Severity,
			Host: l.Host, Type: l.Type, CVE: l.CVE, Tags: l.Tags, EndpointKey: l.EndpointKey,
			FirstSeenAt: l.FirstSeenAt, LastSeenAt: l.LastSeenAt, TimesMitigated: l.TimesMitigated,
			Disposition: l.Disposition, AcceptExpiresAt: l.AcceptExpiresAt,
			DispositionNote: l.DispositionNote, DispositionBy: l.DispositionBy, DispositionAt: l.DispositionAt,
			RecastSeverity: l.RecastSeverity, RecastNote: l.RecastNote, RecastBy: l.RecastBy, RecastAt: l.RecastAt,
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
		Findings:  findings,
		Lifecycle: lifecycle,
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

// ImportFallback records one bundle reference that did not exist locally and
// fell back to its default (NULL).
type ImportFallback struct {
	Field      string `json:"field"`
	ExporterID string `json:"exporter_id"`
}

// ScanImportResult summarizes an applied import.
type ScanImportResult struct {
	ScanID           string           `json:"scan_id"`
	FindingsImported int              `json:"findings_imported"`
	LifecycleCreated int              `json:"lifecycle_created"`
	LifecycleUpdated int              `json:"lifecycle_updated"`
	Fallbacks        []ImportFallback `json:"fallbacks,omitempty"`
}

// ErrScanBundleConflict is returned when importing a bundle whose scan id
// already exists locally under the default (error) conflict policy.
var ErrScanBundleConflict = errors.New("scan already exists")

// ImportScanBundle recreates a scan and its findings on this instance and merges
// the destination lifecycle from the bundle. It runs in one transaction, so a
// malformed bundle leaves no partial state. Referenced entities missing locally
// fall back to NULL — the same default a deleted target/policy leaves behind.
//
// The manifest is validated by the caller (types.ScanBundle.Validate); this
// function still fails closed on any per-row projection error.
func (s *Store) ImportScanBundle(ctx context.Context, b *types.ScanBundle, conflict ImportConflict) (*ScanImportResult, error) {
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
	if err := validateBundleTriage(b); err != nil {
		return nil, err
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

	coveredJSON, err := json.Marshal(b.Scan.CoveredEndpoints)
	if err != nil {
		return nil, err
	}
	if string(coveredJSON) == "null" {
		// The column's CHECK requires an array (or NULL); an absent coverage list
		// imports as NULL, mirroring "no coverage evidence recorded".
		coveredJSON = nil
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO scans (id, state, spec, target_id, template_set_id, scan_policy_id,
		                    source, schedule_id, node_id, nuclei_version, templates_commit, error,
		                    skipped_finding_count, created_at, started_at, finished_at,
		                    discovered_targets, covered_endpoints, coverage_warning)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		scanID, state, b.Scan.Spec, nullStr(scan.TargetID), nullStr(scan.TemplateSetID), nullStr(scan.ScanPolicyID),
		nullStr(b.Scan.Source), nullStr(scan.ScheduleID), nullStr(scan.NodeID), nullStr(b.Scan.NucleiVersion), nullStr(b.Scan.TemplatesCommit), nullStr(errText),
		b.Scan.SkippedFindingCount, b.Scan.CreatedAt, b.Scan.StartedAt, b.Scan.FinishedAt,
		orEmpty(b.Scan.DiscoveredTargets), coveredJSON, nullStr(b.Scan.CoverageWarning),
	); err != nil {
		return nil, fmt.Errorf("insert imported scan: %w", err)
	}

	// Per-occurrence lifecycle: the dedup identity is recomputed from the raw
	// payload (never trusted from the bundle), mapped to the bundle's lifecycle
	// entry by that identity, and the occurrence + lifecycle upsert + link happen
	// per finding. An occurrence whose identity has no lifecycle entry in the
	// bundle (a crafted or older bundle) still gets a synthesized, neutral
	// lifecycle row — every occurrence must link to one.
	lifecycleByKey := make(map[string]types.ScanBundleLifecycle, len(b.Lifecycle))
	for _, l := range b.Lifecycle {
		lifecycleByKey[DedupKey(l.TemplateID, l.MatchedAt, l.ResultDiscriminator)] = l
	}

	result := &ScanImportResult{ScanID: scanID, Fallbacks: fallbacks}
	for _, f := range b.Findings {
		rawProjection, err := findingJSONBProjection(f.Raw)
		if err != nil {
			return nil, fmt.Errorf("scan bundle: finding %q/%q raw payload: %w", f.TemplateID, f.MatchedAt, err)
		}
		discriminator, err := resultDiscriminator(rawProjection)
		if err != nil {
			return nil, fmt.Errorf("scan bundle: finding %q/%q result identity: %w", f.TemplateID, f.MatchedAt, err)
		}
		key := DedupKey(f.TemplateID, f.MatchedAt, discriminator)
		entry, hasEntry := lifecycleByKey[key]
		created, err := upsertImportedLifecycle(ctx, tx, scanID, scan.TargetID, b.Scan.CreatedAt, f, entry, hasEntry, key, discriminator, rawProjection)
		if err != nil {
			return nil, err
		}
		if created {
			result.LifecycleCreated++
		} else {
			result.LifecycleUpdated++
		}
		result.FindingsImported++
	}

	// The imported scan's coverage evidence (exact template+endpoint pairs) can
	// advance the destination's last_covering_scan pointers exactly like a scan
	// completing normally would — detection states stay evidence-driven.
	if err := applyScanCoverage(ctx, tx, scanID); err != nil {
		return nil, fmt.Errorf("apply imported scan coverage: %w", err)
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

// validateBundleTriage enforces the analyst-overlay vocabulary on the bundle's
// lifecycle entries (defense in depth — the DB CHECKs would reject them too)
// and rejects duplicate lifecycle identities, so every recomputed dedup key
// maps to at most one bundle entry.
func validateBundleTriage(b *types.ScanBundle) error {
	seen := make(map[string]struct{}, len(b.Lifecycle))
	for i, l := range b.Lifecycle {
		if !ValidDisposition(l.Disposition) {
			return fmt.Errorf("scan bundle: lifecycle %d has invalid disposition %q", i, l.Disposition)
		}
		if l.RecastSeverity != "" && !ValidSeverity(l.RecastSeverity) {
			return fmt.Errorf("scan bundle: lifecycle %d has invalid recast severity %q", i, l.RecastSeverity)
		}
		key := DedupKey(l.TemplateID, l.MatchedAt, l.ResultDiscriminator)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("scan bundle: lifecycle %d duplicates an earlier lifecycle identity", i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// upsertImportedLifecycle inserts one occurrence and upserts its lifecycle row,
// mirroring IngestFinding's chronology rules plus the bundle's analyst overlays:
//
//   - first/last-seen follow the stable (scan.created_at, scan.id) order, so an
//     older imported scan can never move last_seen backwards;
//   - times_mitigated takes the greatest of the local and bundle counters, so no
//     mitigation history is ever lost by a merge;
//   - the bundle's disposition applies only when the local row has none, and its
//     recast only when the local row has none — a destination analyst's existing
//     overlay always wins over an imported one.
//
// It reports whether the lifecycle row was created.
func upsertImportedLifecycle(ctx context.Context, tx pgx.Tx, scanID, targetID string, scanCreatedAt time.Time,
	f types.ScanBundleFinding, entry types.ScanBundleLifecycle, hasEntry bool, key, discriminator string, rawProjection []byte) (bool, error) {
	finding := types.NucleiFinding{
		TemplateID: f.TemplateID,
		Type:       f.Type,
		Host:       f.Host,
		MatchedAt:  f.MatchedAt,
		Info: types.NucleiInfo{
			Name:     f.Name,
			Severity: f.Severity,
			Tags:     orEmpty(f.Tags),
		},
	}
	if len(f.CVE) > 0 {
		finding.Info.Classification = &types.NucleiClassification{CVEID: f.CVE}
	}
	finding = findingTextProjection(finding)
	rawLine := findingRawLine(f.Raw)
	endpointKey := postgresText(types.EndpointKey(f.MatchedAt, f.Type))

	// The occurrence's scope is the scan's resolved scope (findings_scan_scope_fk
	// constrains target_id to the owning scan), so the exported occurrence's
	// denormalized target copy is replaced by the fallback-resolved one.
	var occID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO findings
		   (scan_id, target_id, dedup_key, result_discriminator, template_id, name, severity,
		    host, matched_at, type, cve, tags, raw, raw_line, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 RETURNING id`,
		scanID, nullStr(targetID), key, discriminator, finding.TemplateID, finding.Info.Name, finding.Info.Severity,
		finding.Host, finding.MatchedAt, finding.Type, orEmpty(finding.CVEs()), orEmpty(finding.Info.Tags), rawProjection, rawLine, f.CreatedAt,
	).Scan(&occID); err != nil {
		return false, fmt.Errorf("insert imported occurrence: %w", err)
	}

	firstSeenAt, lastSeenAt := f.CreatedAt, f.CreatedAt
	timesMitigated := 0
	disposition := "none"
	var acceptExpiresAt *time.Time
	var dispositionNote, dispositionBy, recastSeverity, recastNote, recastBy string
	var dispositionAt, recastAt *time.Time
	if hasEntry {
		if !entry.FirstSeenAt.IsZero() {
			firstSeenAt = entry.FirstSeenAt
		}
		if !entry.LastSeenAt.IsZero() {
			lastSeenAt = entry.LastSeenAt
		}
		if entry.TimesMitigated > 0 {
			timesMitigated = entry.TimesMitigated
		}
		disposition = entry.Disposition
		acceptExpiresAt = entry.AcceptExpiresAt
		dispositionNote, dispositionBy = entry.DispositionNote, entry.DispositionBy
		dispositionAt = entry.DispositionAt
		recastSeverity, recastNote, recastBy = entry.RecastSeverity, entry.RecastNote, entry.RecastBy
		recastAt = entry.RecastAt
	}

	// (scan.created_at, scan.id) tuple comparisons keep the lifecycle chronology
	// stable: an imported scan from an older time never moves last_seen backwards
	// or first_seen forwards.
	const incomingNewer = `COALESCE((
		SELECT (current_scan.created_at, current_scan.id) < ($26::timestamptz, $27::uuid)
		  FROM scans current_scan
		 WHERE current_scan.id = finding_lifecycle.last_seen_scan
	), true)`
	const incomingOlder = `COALESCE((
		SELECT ($26::timestamptz, $27::uuid) < (current_scan.created_at, current_scan.id)
		  FROM scans current_scan
		 WHERE current_scan.id = finding_lifecycle.first_seen_scan
	), true)`
	upsert := fmt.Sprintf(
		`INSERT INTO finding_lifecycle
		   (dedup_key, result_discriminator, template_id, name, severity, host,
		    matched_at, endpoint_key, type, cve, tags, first_seen_scan, first_seen_at, last_seen_scan,
		    last_seen_at, latest_occurrence_id, times_mitigated,
		    disposition, accept_expires_at, disposition_note, disposition_by, disposition_at,
		    recast_severity, recast_note, recast_by, recast_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $12, $14, $15, $16,
		         $17, $18, $19, $20, $21, $22, $23, $24, $25)
		 ON CONFLICT (dedup_key) DO UPDATE SET
		    first_seen_scan      = CASE WHEN %[2]s THEN excluded.first_seen_scan ELSE finding_lifecycle.first_seen_scan END,
		    first_seen_at        = least(finding_lifecycle.first_seen_at, excluded.first_seen_at),
		    last_seen_scan       = CASE WHEN %[1]s THEN excluded.last_seen_scan ELSE finding_lifecycle.last_seen_scan END,
		    last_seen_at         = greatest(finding_lifecycle.last_seen_at, excluded.last_seen_at),
		    name                 = CASE WHEN %[1]s THEN excluded.name ELSE finding_lifecycle.name END,
		    severity             = CASE WHEN %[1]s THEN excluded.severity ELSE finding_lifecycle.severity END,
		    host                 = CASE WHEN %[1]s THEN excluded.host ELSE finding_lifecycle.host END,
		    matched_at           = CASE WHEN %[1]s THEN excluded.matched_at ELSE finding_lifecycle.matched_at END,
		    endpoint_key         = CASE WHEN %[1]s THEN excluded.endpoint_key ELSE finding_lifecycle.endpoint_key END,
		    type                 = CASE WHEN %[1]s THEN excluded.type ELSE finding_lifecycle.type END,
		    cve                  = CASE WHEN %[1]s THEN excluded.cve ELSE finding_lifecycle.cve END,
		    tags                 = CASE WHEN %[1]s THEN excluded.tags ELSE finding_lifecycle.tags END,
		    result_discriminator = excluded.result_discriminator,
		    latest_occurrence_id = CASE WHEN %[1]s THEN excluded.latest_occurrence_id ELSE finding_lifecycle.latest_occurrence_id END,
		    times_mitigated      = greatest(finding_lifecycle.times_mitigated, excluded.times_mitigated),
		    disposition          = CASE
		                               WHEN finding_lifecycle.disposition <> 'none' OR finding_lifecycle.accept_expires_at IS NOT NULL
		                               THEN finding_lifecycle.disposition ELSE excluded.disposition END,
		    accept_expires_at    = CASE
		                               WHEN finding_lifecycle.disposition <> 'none' OR finding_lifecycle.accept_expires_at IS NOT NULL
		                               THEN finding_lifecycle.accept_expires_at ELSE excluded.accept_expires_at END,
		    disposition_note     = CASE
		                               WHEN finding_lifecycle.disposition <> 'none' OR finding_lifecycle.accept_expires_at IS NOT NULL
		                               THEN finding_lifecycle.disposition_note ELSE excluded.disposition_note END,
		    disposition_by       = CASE
		                               WHEN finding_lifecycle.disposition <> 'none' OR finding_lifecycle.accept_expires_at IS NOT NULL
		                               THEN finding_lifecycle.disposition_by ELSE excluded.disposition_by END,
		    disposition_at       = CASE
		                               WHEN finding_lifecycle.disposition <> 'none' OR finding_lifecycle.accept_expires_at IS NOT NULL
		                               THEN finding_lifecycle.disposition_at ELSE excluded.disposition_at END,
		    recast_severity      = CASE
		                               WHEN finding_lifecycle.recast_severity IS NOT NULL
		                               THEN finding_lifecycle.recast_severity ELSE excluded.recast_severity END,
		    recast_note          = CASE
		                               WHEN finding_lifecycle.recast_severity IS NOT NULL
		                               THEN finding_lifecycle.recast_note ELSE excluded.recast_note END,
		    recast_by            = CASE
		                               WHEN finding_lifecycle.recast_severity IS NOT NULL
		                               THEN finding_lifecycle.recast_by ELSE excluded.recast_by END,
		    recast_at            = CASE
		                               WHEN finding_lifecycle.recast_severity IS NOT NULL
		                               THEN finding_lifecycle.recast_at ELSE excluded.recast_at END
		 RETURNING id, (xmax = 0) AS created`,
		incomingNewer, incomingOlder)
	var lcID int64
	var lcCreated bool
	if err := tx.QueryRow(ctx, upsert,
		key, discriminator, finding.TemplateID, finding.Info.Name, finding.Info.Severity, finding.Host,
		finding.MatchedAt, endpointKey, finding.Type, orEmpty(finding.CVEs()), orEmpty(finding.Info.Tags),
		scanID, firstSeenAt, lastSeenAt, occID, timesMitigated,
		disposition, acceptExpiresAt, nullStr(dispositionNote), nullStr(dispositionBy), dispositionAt,
		nullStr(recastSeverity), nullStr(recastNote), nullStr(recastBy), recastAt,
		scanCreatedAt, scanID,
	).Scan(&lcID, &lcCreated); err != nil {
		return false, fmt.Errorf("upsert imported lifecycle: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET finding_id = $1 WHERE id = $2`, lcID, occID); err != nil {
		return false, fmt.Errorf("link imported occurrence: %w", err)
	}
	return lcCreated, nil
}

// applyScanCoverage advances the destination's last_covering_scan evidence
// pointers for the imported scan's exact coverage pairs — the same evidence
// update MarkComplete performs at normal completion, without flipping the scan
// state or its timestamps.
func applyScanCoverage(ctx context.Context, tx pgx.Tx, scanID string) error {
	_, err := tx.Exec(ctx,
		`WITH completed_scan AS (
		    SELECT id, target_id, covered_endpoints, skipped_finding_count, created_at
		      FROM scans WHERE id = $1
		 ),
		 coverage_pairs AS MATERIALIZED (
		    SELECT pair->>'template_id' AS template_id,
		           pair->>'endpoint' AS endpoint
		      FROM completed_scan
		      CROSS JOIN LATERAL jsonb_array_elements(
		          CASE WHEN completed_scan.skipped_finding_count = 0
		               THEN COALESCE(completed_scan.covered_endpoints, '[]'::jsonb)
		               ELSE '[]'::jsonb END
		      ) AS pair
		     WHERE jsonb_typeof(pair) = 'object'
		 ),
		 candidate_lifecycle AS MATERIALIZED (
		    SELECT lifecycle.id
		      FROM coverage_pairs coverage
		      JOIN finding_lifecycle lifecycle
		        ON lifecycle.template_id = coverage.template_id
		       AND lifecycle.endpoint_key = coverage.endpoint
		     WHERE lifecycle.endpoint_key <> ''
		    UNION
		    SELECT observed.finding_id
		      FROM completed_scan
		      JOIN findings observed ON observed.scan_id = completed_scan.id
		     WHERE observed.finding_id IS NOT NULL
		 )
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
		    )`,
		scanID)
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
