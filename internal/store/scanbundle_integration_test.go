package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestCoverageOriginDefaultsToUntrustedPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)
	scanID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO scans (id, state, spec) VALUES ($1, $2, $3)`,
		scanID, types.ScanFailed, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("insert scan without coverage origin: %v", err)
	}

	var origin string
	if err := st.pool.QueryRow(ctx, `SELECT coverage_origin FROM scans WHERE id = $1`, scanID).Scan(&origin); err != nil {
		t.Fatalf("read default coverage origin: %v", err)
	}
	if origin != CoverageOriginImportUntrusted {
		t.Fatalf("default coverage origin = %q, want %q", origin, CoverageOriginImportUntrusted)
	}
}

// TestScanBundleRoundTripPostgres exercises the complete export → import →
// re-export cycle against a real migrated PostgreSQL database: a scan with
// findings, analyst overlays, discovery evidence and coverage is exported from
// one instance and imported into a second, empty instance; the imported scan
// must reproduce every occurrence and lifecycle detail. Coverage claims and
// warnings from an external bundle are retained in the portable manifest but
// are not trusted as destination evidence by the default import mode, so the
// safe re-export omits them.
//
//	NSC_TEST_DATABASE_URL=postgres://... go test ./internal/store -run TestScanBundleRoundTripPostgres
func TestScanBundleRoundTripPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	origin := openIsolatedPostgres(t, ctx, dsn)
	dest := openIsolatedPostgres(t, ctx, dsn)

	suffix := types.NewID()
	target, err := origin.CreateTarget(ctx, Target{Name: "bundle-roundtrip-" + suffix, Hosts: []string{"roundtrip.invalid"}})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	templateSet, err := origin.CreateTemplateSet(ctx, TemplateSet{Name: "bundle-set-" + suffix, Mode: TemplateSetModeAll})
	if err != nil {
		t.Fatalf("create template set: %v", err)
	}
	rateLimit := 25
	hostDiscovery := true
	policy, err := origin.CreateScanPolicy(ctx, ScanPolicy{
		Name:                   "bundle-policy-" + suffix,
		TemplateSetID:          templateSet.ID,
		RateLimit:              &rateLimit,
		DiscoveryHostDiscovery: &hostDiscovery,
	})
	if err != nil {
		t.Fatalf("create scan policy: %v", err)
	}

	spec := types.ScanSpec{
		Targets: target.Hosts,
		Templates: types.TemplateSelector{
			TemplateIDs:     []string{"tpl-a", "tpl-b"},
			TemplatesCommit: "roundtrip-commit",
		},
	}
	scanID, err := origin.CreateScan(ctx, spec, ScanLink{
		TargetID:      target.ID,
		TemplateSetID: templateSet.ID,
		ScanPolicyID:  policy.ID,
		Source:        "manual",
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}

	// Two occurrences: one http finding (auto-mitigation-eligible endpoint), one
	// dns finding. Both get analyst overlays so import must carry them.
	findings := []types.NucleiFinding{
		{
			TemplateID: "tpl-a",
			Host:       "roundtrip.invalid",
			MatchedAt:  "https://roundtrip.invalid/",
			Type:       "http",
			Info: types.NucleiInfo{
				Name:     "roundtrip-http-check",
				Severity: "high",
				Tags:     []string{"roundtrip", "http"},
			},
		},
		{
			TemplateID: "tpl-b",
			Host:       "roundtrip.invalid",
			MatchedAt:  "roundtrip.invalid:53",
			Type:       "dns",
			Info: types.NucleiInfo{
				Name:     "roundtrip-dns-check",
				Severity: "medium",
				Tags:     []string{"roundtrip", "dns"},
			},
		},
	}
	for _, finding := range findings {
		raw, err := json.Marshal(finding)
		if err != nil {
			t.Fatalf("marshal finding: %v", err)
		}
		if err := origin.IngestFinding(ctx, scanID, target.ID, finding, raw); err != nil {
			t.Fatalf("ingest finding: %v", err)
		}
	}

	if err := origin.SetScanDiscovered(ctx, scanID, []string{"roundtrip.invalid:443", "roundtrip.invalid:53"}); err != nil {
		t.Fatalf("set discovered targets: %v", err)
	}
	coverage := []types.EndpointCoverage{
		{TemplateID: "tpl-a", Endpoint: "roundtrip.invalid:443"},
		{TemplateID: "tpl-b", Endpoint: "roundtrip.invalid:53"},
	}
	if err := origin.SetScanCoverage(ctx, scanID, coverage, "source trace warning"); err != nil {
		t.Fatalf("set scan coverage: %v", err)
	}
	if err := origin.MarkComplete(ctx, scanID, "3.3.0", "roundtrip-commit"); err != nil {
		t.Fatalf("complete scan: %v", err)
	}

	// The destination instance mirrors the same config records (as a real
	// deployment move would), so the bundle's references resolve there too.
	if _, err := dest.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts, tags, created_by) VALUES ($1, $2, $3, $4, $5)`,
		target.ID, target.Name, target.Hosts, target.Tags, nullStr(target.CreatedBy)); err != nil {
		t.Fatalf("mirror target on destination: %v", err)
	}
	if _, err := dest.pool.Exec(ctx,
		`INSERT INTO template_sets (id, name, mode, created_by) VALUES ($1, $2, $3, $4)`,
		templateSet.ID, templateSet.Name, templateSet.Mode, nullStr(templateSet.CreatedBy)); err != nil {
		t.Fatalf("mirror template set on destination: %v", err)
	}
	if _, err := dest.pool.Exec(ctx,
		`INSERT INTO scan_policies (id, name, template_set_id, rate_limit, discovery_enabled, discovery_host_discovery)
		 VALUES ($1, $2, $3, $4, COALESCE($5, TRUE), $6)`,
		policy.ID, policy.Name, policy.TemplateSetID, policy.RateLimit, policy.DiscoveryEnabled, policy.DiscoveryHostDiscovery); err != nil {
		t.Fatalf("mirror scan policy on destination: %v", err)
	}

	// Analyst overlays on the source lifecycle rows. These must NOT leak into the
	// bundle: a bundle carries the scan's results, not the exporter's analysis,
	// so the destination re-derives its own lifecycle (a .ness file, not one).
	rows, _, err := origin.ListLifecycleFindings(ctx, FindingQuery{}, 50, 0)
	if err != nil {
		t.Fatalf("list lifecycle: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 lifecycle rows, got %d", len(rows))
	}
	byTemplate := map[string]LifecycleRow{}
	for _, row := range rows {
		byTemplate[row.TemplateID] = row
	}
	if err := origin.SetDisposition(ctx, byTemplate["tpl-a"].ID, "accepted", "import test", "test-analyst", nil); err != nil {
		t.Fatalf("set disposition: %v", err)
	}
	if err := origin.RecastSeverity(ctx, byTemplate["tpl-b"].ID, "critical", "import test", "test-analyst"); err != nil {
		t.Fatalf("recast severity: %v", err)
	}

	bundle, err := origin.ScanBundleForExport(ctx, scanID)
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("exported bundle fails validation: %v", err)
	}
	if bundle.Scan.State != string(types.ScanComplete) || bundle.Scan.TemplatesCommit != "roundtrip-commit" {
		t.Fatalf("bundle scan record wrong: state=%s commit=%s", bundle.Scan.State, bundle.Scan.TemplatesCommit)
	}
	if len(bundle.Findings) != 2 {
		t.Fatalf("bundle contents wrong: %d findings", len(bundle.Findings))
	}
	if bundle.Config.TargetID != target.ID || bundle.Config.TemplateSetID != templateSet.ID || bundle.Config.ScanPolicyID != policy.ID {
		t.Fatalf("bundle config refs wrong: %+v", bundle.Config)
	}
	if bundle.Config.Target == nil || bundle.Config.TemplateSet == nil || bundle.Config.ScanPolicy == nil {
		t.Fatalf("bundle config snapshots missing")
	}
	if bundle.Config.ScanPolicy.DiscoveryHostDiscovery == nil || !*bundle.Config.ScanPolicy.DiscoveryHostDiscovery {
		t.Fatalf("bundle omitted forced host-discovery setting: %+v", bundle.Config.ScanPolicy)
	}

	// Import into the empty destination instance.
	result, err := dest.ImportScanBundle(ctx, bundle, ImportConflictError, ImportCoverageIgnore)
	if err != nil {
		t.Fatalf("import bundle: %v", err)
	}
	if result.ScanID != scanID || result.FindingsImported != 2 || result.LifecycleCreated != 2 {
		t.Fatalf("import result wrong: %+v", result)
	}

	// The imported scan must carry the full record.
	importedScan, err := dest.GetScan(ctx, scanID)
	if err != nil {
		t.Fatalf("get imported scan: %v", err)
	}
	if importedScan.State != string(types.ScanComplete) ||
		importedScan.NucleiVersion != "3.3.0" || importedScan.TemplatesCommit != "roundtrip-commit" ||
		importedScan.TargetID != target.ID || importedScan.TemplateSetID != templateSet.ID || importedScan.ScanPolicyID != policy.ID {
		t.Fatalf("imported scan record wrong: %+v", importedScan)
	}
	var importedSource string
	if err := dest.pool.QueryRow(ctx, `SELECT source FROM scans WHERE id = $1`, scanID).Scan(&importedSource); err != nil {
		t.Fatalf("read imported source: %v", err)
	}
	if importedSource != "manual" {
		t.Fatalf("imported source wrong: %q", importedSource)
	}
	if len(importedScan.DiscoveredTargets) != 2 {
		t.Fatalf("imported discovered targets lost: %v", importedScan.DiscoveredTargets)
	}
	if importedScan.CoveredEndpoints != nil {
		t.Fatalf("imported coverage must be unknown, got %v", importedScan.CoveredEndpoints)
	}
	if importedScan.CoverageWarning != "" {
		t.Fatalf("imported coverage warning must be discarded, got %q", importedScan.CoverageWarning)
	}

	// Occurrences must be reproduced, and the composite scope FK satisfied.
	occurrences, total, err := dest.ListFindings(ctx, FindingFilter{ScanID: scanID, Limit: 50})
	if err != nil {
		t.Fatalf("list imported occurrences: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected 2 imported occurrences, got %d", total)
	}
	occByTemplate := map[string]FindingRow{}
	for _, occ := range occurrences {
		occByTemplate[occ.TemplateID] = occ
	}
	if _, ok := occByTemplate["tpl-a"]; !ok {
		t.Fatalf("tpl-a occurrence missing")
	}

	// Lifecycle: both rows are re-derived by the destination's own rules with NO
	// overlays (analyst dispositions/recasts are never exported), plus occurrence
	// links and coverage evidence.
	lifecycle, _, err := dest.ListLifecycleFindings(ctx, FindingQuery{}, 50, 0)
	if err != nil {
		t.Fatalf("list imported lifecycle: %v", err)
	}
	if len(lifecycle) != 2 {
		t.Fatalf("expected 2 lifecycle rows, got %d", len(lifecycle))
	}
	lcByTemplate := map[string]LifecycleRow{}
	for _, row := range lifecycle {
		lcByTemplate[row.TemplateID] = row
	}
	if lcByTemplate["tpl-a"].Disposition != "none" {
		t.Fatalf("imported disposition must be none (overlays are never carried), got %q", lcByTemplate["tpl-a"].Disposition)
	}
	if lcByTemplate["tpl-b"].RecastSeverity != nil {
		t.Fatalf("imported recast must be nil (overlays are never carried), got %v", lcByTemplate["tpl-b"].RecastSeverity)
	}
	if lcByTemplate["tpl-a"].LastSeenScan == nil || *lcByTemplate["tpl-a"].LastSeenScan != scanID {
		t.Fatalf("last_seen_scan evidence missing after import: %v", lcByTemplate["tpl-a"].LastSeenScan)
	}

	// Re-export from the destination: the scan and its results must round-trip
	// exactly (config snapshots may differ only in that the refs resolved on the
	// origin instance — here both are the same ids since the destination is empty).
	reBundle, err := dest.ScanBundleForExport(ctx, scanID)
	if err != nil {
		t.Fatalf("re-export bundle: %v", err)
	}
	expectedBundle := *bundle
	expectedBundle.ExportedAt = time.Time{}
	expectedBundle.Scan.CoveredEndpoints = nil
	expectedBundle.Scan.CoverageWarning = ""
	destinationBundle := *reBundle
	destinationBundle.ExportedAt = time.Time{}
	originJSON, _ := json.Marshal(&expectedBundle)
	destJSON, _ := json.Marshal(&destinationBundle)
	if string(originJSON) != string(destJSON) {
		t.Fatalf("re-export diverges from origin bundle:\norigin: %s\ndest:   %s", originJSON, destJSON)
	}

	// Default conflict policy refuses to overwrite.
	if _, err := dest.ImportScanBundle(ctx, bundle, ImportConflictError, ImportCoverageIgnore); !errors.Is(err, ErrScanBundleConflict) {
		t.Fatalf("expected ErrScanBundleConflict, got %v", err)
	}
	// Duplicate policy mints a new id and keeps the original intact.
	dupResult, err := dest.ImportScanBundle(ctx, bundle, ImportConflictDuplicate, ImportCoverageIgnore)
	if err != nil {
		t.Fatalf("duplicate import: %v", err)
	}
	if dupResult.ScanID == scanID {
		t.Fatalf("duplicate import reused the original id")
	}
	if _, err := dest.GetScan(ctx, dupResult.ScanID); err != nil {
		t.Fatalf("get duplicated scan: %v", err)
	}
	if _, err := dest.GetScan(ctx, scanID); err != nil {
		t.Fatalf("original scan clobbered by duplicate import: %v", err)
	}
}

// TestScanBundleImportFallbackPostgres exercises the fail-soft behaviors:
// missing references fall back to NULL (never hard-error), an in-flight bundle
// imports as failed, and a destination analyst's existing overlay always wins
// over an imported one.
func TestScanBundleImportFallbackPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dest := openIsolatedPostgres(t, ctx, dsn)

	suffix := types.NewID()
	target, err := dest.CreateTarget(ctx, Target{Name: "bundle-fallback-" + suffix, Hosts: []string{"fallback.invalid"}})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	finding := types.NucleiFinding{
		TemplateID: "tpl-fallback",
		Host:       "fallback.invalid",
		MatchedAt:  "https://fallback.invalid/",
		Type:       "http",
		Info:       types.NucleiInfo{Name: "fallback-check", Severity: "info"},
	}
	raw, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	firstScanID, err := dest.CreateScan(ctx, types.ScanSpec{Targets: target.Hosts}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	if err := dest.IngestFinding(ctx, firstScanID, target.ID, finding, raw); err != nil {
		t.Fatalf("ingest finding: %v", err)
	}
	// The local analyst already triaged this finding: the bundle must not
	// overwrite the destination overlay.
	rows, _, err := dest.ListLifecycleFindings(ctx, FindingQuery{}, 50, 0)
	if err != nil {
		t.Fatalf("list lifecycle: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 lifecycle row, got %d", len(rows))
	}
	if err := dest.SetDisposition(ctx, rows[0].ID, "false_positive", "local analyst", "analyst-bob", nil); err != nil {
		t.Fatalf("set local disposition: %v", err)
	}
	critical := "critical"
	if err := dest.RecastSeverity(ctx, rows[0].ID, critical, "local analyst", "analyst-bob"); err != nil {
		t.Fatalf("set local recast: %v", err)
	}

	// A bundle whose every reference is unknown locally, exported while the scan
	// was still running. Like any bundle it carries only the scan's results —
	// never a lifecycle or analyst analysis — so nothing can overwrite the
	// local overlay even in principle.
	bundle := &types.ScanBundle{
		Format:        types.ScanBundleFormat,
		FormatVersion: types.ScanBundleFormatVersion,
		ExportedAt:    time.Now().UTC(),
		Config: types.ScanBundleConfig{
			TargetID:      "11111111-1111-1111-1111-111111111111",
			TemplateSetID: "22222222-2222-2222-2222-222222222222",
			ScanPolicyID:  "33333333-3333-3333-3333-333333333333",
			NodeID:        "44444444-4444-4444-4444-444444444444",
			ScheduleID:    "55555555-5555-5555-5555-555555555555",
		},
		Scan: types.ScanBundleScan{
			ID:        "66666666-6666-6666-6666-666666666666",
			State:     string(types.ScanRunning),
			Source:    "schedule",
			CreatedAt: time.Now().UTC().Add(-time.Hour),
			Spec:      json.RawMessage(`{"targets":["fallback.invalid"]}`),
		},
		Findings: []types.ScanBundleFinding{{
			TemplateID: finding.TemplateID,
			Name:       finding.Info.Name,
			Severity:   finding.Info.Severity,
			Host:       finding.Host,
			MatchedAt:  finding.MatchedAt,
			Type:       finding.Type,
			CreatedAt:  time.Now().UTC().Add(-time.Hour),
			Raw:        raw,
		}},
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("test bundle fails validation: %v", err)
	}

	result, err := dest.ImportScanBundle(ctx, bundle, ImportConflictError, ImportCoverageIgnore)
	if err != nil {
		t.Fatalf("import fallback bundle: %v", err)
	}
	if len(result.Fallbacks) != 5 {
		t.Fatalf("expected 5 fallbacks, got %v", result.Fallbacks)
	}

	imported, err := dest.GetScan(ctx, bundle.Scan.ID)
	if err != nil {
		t.Fatalf("get imported scan: %v", err)
	}
	if imported.State != string(types.ScanFailed) {
		t.Fatalf("in-flight bundle must import as failed, got %q", imported.State)
	}
	if imported.Error == "" {
		t.Fatalf("failed import must carry an explanatory error")
	}
	if imported.TargetID != "" || imported.TemplateSetID != "" || imported.ScanPolicyID != "" ||
		imported.NodeID != "" {
		t.Fatalf("missing references must fall back to NULL: %+v", imported)
	}
	var importedSchedule *string
	if err := dest.pool.QueryRow(ctx, `SELECT schedule_id FROM scans WHERE id = $1`, bundle.Scan.ID).Scan(&importedSchedule); err != nil {
		t.Fatalf("read imported schedule_id: %v", err)
	}
	if importedSchedule != nil {
		t.Fatalf("missing schedule must fall back to NULL, got %q", *importedSchedule)
	}

	// The destination analyst's overlay must still win (import never carries an
	// analysis), the local occurrence count is now two, and the imported
	// occurrence did not roll the lifecycle back to the bundle's older dates.
	lifecycle, _, err := dest.ListLifecycleFindings(ctx, FindingQuery{}, 50, 0)
	if err != nil {
		t.Fatalf("list lifecycle: %v", err)
	}
	if len(lifecycle) != 1 {
		t.Fatalf("expected 1 lifecycle row, got %d", len(lifecycle))
	}
	if lifecycle[0].Disposition != "false_positive" {
		t.Fatalf("destination overlay lost: %q", lifecycle[0].Disposition)
	}
	if lifecycle[0].RecastSeverity == nil || *lifecycle[0].RecastSeverity != critical {
		t.Fatalf("destination recast lost: %v", lifecycle[0].RecastSeverity)
	}
	if lifecycle[0].TimesMitigated != 0 {
		t.Fatalf("unexpected mitigation count: %d", lifecycle[0].TimesMitigated)
	}
	occurrences, total, err := dest.ListFindings(ctx, FindingFilter{ScanID: bundle.Scan.ID, Limit: 50})
	if err != nil {
		t.Fatalf("list imported occurrences: %v", err)
	}
	if total != 1 || len(occurrences) != 1 {
		t.Fatalf("expected 1 occurrence on the imported scan, got %d", total)
	}
}

// TestScanBundleImportCoverageCannotAffectRepairPostgres locks the review
// finding that imported coverage is untrusted lifecycle evidence: a coverage-
// only manifest must not advance the destination's detection state immediately
// or during later scan-deletion repair. Coverage evidence on import is anchored
// on the occurrences the bundle actually carries, never on claimed endpoints.
//
//	NSC_TEST_DATABASE_URL=postgres://... go test ./internal/store -run TestScanBundleImportCoverageCannotAffectRepairPostgres
func TestScanBundleImportCoverageCannotAffectRepairPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dest := openIsolatedPostgres(t, ctx, dsn)

	suffix := types.NewID()
	target, err := dest.CreateTarget(ctx, Target{Name: "coverage-import-" + suffix, Hosts: []string{"coverage.invalid"}})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	// A real scan observes tpl-cover once on fine coverage.invalid:443 and
	// completes, so the lifecycle row's last_covering_scan points at it.
	finding := types.NucleiFinding{
		TemplateID: "tpl-close",
		Host:       "coverage.invalid",
		MatchedAt:  "https://coverage.invalid/",
		Type:       "http",
		Info:       types.NucleiInfo{Name: "close-check", Severity: "high"},
	}
	raw, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	firstScanID, err := dest.CreateScan(ctx, types.ScanSpec{Targets: target.Hosts}, ScanLink{TargetID: target.ID, Source: "manual"})
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	if err := dest.IngestFinding(ctx, firstScanID, target.ID, finding, raw); err != nil {
		t.Fatalf("ingest finding: %v", err)
	}
	coverage := []types.EndpointCoverage{{TemplateID: "tpl-close", Endpoint: "coverage.invalid:443"}}
	if err := dest.SetScanCoverage(ctx, firstScanID, coverage, ""); err != nil {
		t.Fatalf("set coverage: %v", err)
	}
	if err := dest.MarkComplete(ctx, firstScanID, "3.3.0", "coverage-commit"); err != nil {
		t.Fatalf("complete scan: %v", err)
	}
	var coveringBefore string
	if err := dest.pool.QueryRow(ctx,
		`SELECT last_covering_scan FROM finding_lifecycle WHERE template_id = $1`, "tpl-close").Scan(&coveringBefore); err != nil {
		t.Fatalf("read covering scan: %v", err)
	}
	if coveringBefore != firstScanID {
		t.Fatalf("covering scan = %q, want %q", coveringBefore, firstScanID)
	}

	// A second real observation becomes the latest covering scan. Deleting it
	// later will trigger lifecycle repair while the first observation remains.
	repairScanID, err := dest.CreateScan(ctx, types.ScanSpec{Targets: target.Hosts}, ScanLink{TargetID: target.ID, Source: "manual"})
	if err != nil {
		t.Fatalf("create repair-trigger scan: %v", err)
	}
	if err := dest.IngestFinding(ctx, repairScanID, target.ID, finding, raw); err != nil {
		t.Fatalf("ingest repair-trigger finding: %v", err)
	}
	if err := dest.SetScanCoverage(ctx, repairScanID, coverage, ""); err != nil {
		t.Fatalf("set repair-trigger coverage: %v", err)
	}
	if err := dest.MarkComplete(ctx, repairScanID, "3.3.0", "coverage-commit"); err != nil {
		t.Fatalf("complete repair-trigger scan: %v", err)
	}
	if err := dest.pool.QueryRow(ctx,
		`SELECT last_covering_scan FROM finding_lifecycle WHERE template_id = $1`, "tpl-close").Scan(&coveringBefore); err != nil {
		t.Fatalf("read latest covering scan: %v", err)
	}
	if coveringBefore != repairScanID {
		t.Fatalf("covering scan = %q, want repair-trigger scan %q", coveringBefore, repairScanID)
	}

	// A forged bundle: complete, newer, attributing the exact coverage pair, but
	// carrying zero findings. Under the old coverage_pairs join this would click
	// last_covering_scan forward and close the finding; import must refuse to.
	bundle := &types.ScanBundle{
		Format:        types.ScanBundleFormat,
		FormatVersion: types.ScanBundleFormatVersion,
		ExportedAt:    time.Now().UTC(),
		Config:        types.ScanBundleConfig{TargetID: target.ID},
		Scan: types.ScanBundleScan{
			ID:               types.NewID(),
			State:            string(types.ScanComplete),
			Source:           "manual",
			CreatedAt:        time.Now().UTC().Add(time.Minute),
			CoveredEndpoints: coverage,
			CoverageWarning:  "forged exporter warning",
			Spec:             json.RawMessage(`{"targets":["coverage.invalid"]}`),
		},
		Findings: nil,
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("forged bundle fails validation: %v", err)
	}
	result, err := dest.ImportScanBundle(ctx, bundle, ImportConflictError, ImportCoverageIgnore)
	if err != nil {
		t.Fatalf("import coverage-only bundle: %v", err)
	}
	if result.FindingsImported != 0 {
		t.Fatalf("expected 0 findings imported, got %d", result.FindingsImported)
	}
	var importedCoverageIsNull, importedCoverageWarningIsNull bool
	var importedCoverageOrigin string
	if err := dest.pool.QueryRow(ctx,
		`SELECT covered_endpoints IS NULL, coverage_warning IS NULL, coverage_origin FROM scans WHERE id = $1`, bundle.Scan.ID).
		Scan(&importedCoverageIsNull, &importedCoverageWarningIsNull, &importedCoverageOrigin); err != nil {
		t.Fatalf("read imported coverage state: %v", err)
	}
	if !importedCoverageIsNull {
		t.Fatal("imported covered_endpoints must be discarded as untrusted evidence")
	}
	if !importedCoverageWarningIsNull {
		t.Fatal("imported coverage_warning must be discarded with untrusted coverage")
	}
	if importedCoverageOrigin != CoverageOriginImportUntrusted {
		t.Fatalf("imported coverage origin = %q, want %q", importedCoverageOrigin, CoverageOriginImportUntrusted)
	}
	// Simulate a legacy/import writer that left a claim in the shared column:
	// the durable untrusted origin must still prevent deferred repair from using it.
	if _, err := dest.pool.Exec(ctx,
		`UPDATE scans SET covered_endpoints = $1::jsonb WHERE id = $2`, coverage, bundle.Scan.ID); err != nil {
		t.Fatalf("install legacy imported coverage claim: %v", err)
	}

	// Deleting the newer real scan triggers repair. The forged imported scan must
	// not replace the surviving real scan as mitigation evidence.
	if _, _, err := dest.DeleteScan(ctx, repairScanID); err != nil {
		t.Fatalf("delete repair-trigger scan: %v", err)
	}
	var coveringAfter string
	if err := dest.pool.QueryRow(ctx,
		`SELECT last_covering_scan FROM finding_lifecycle WHERE template_id = $1`, "tpl-close").Scan(&coveringAfter); err != nil {
		t.Fatalf("read covering scan after: %v", err)
	}
	if coveringAfter != firstScanID {
		t.Fatalf("coverage-only import moved last_covering_scan to %q (want %q)", coveringAfter, firstScanID)
	}
	lifecycle, _, err := dest.ListLifecycleFindings(ctx, FindingQuery{}, 50, 0)
	if err != nil {
		t.Fatalf("list lifecycle after repair: %v", err)
	}
	if len(lifecycle) != 1 || lifecycle[0].DetectionState == "mitigated" {
		t.Fatalf("forged imported coverage changed detection state: %+v", lifecycle)
	}
}
