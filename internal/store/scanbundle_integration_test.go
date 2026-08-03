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

// TestScanBundleRoundTripPostgres exercises the complete export → import →
// re-export cycle against a real migrated PostgreSQL database: a scan with
// findings, analyst overlays, discovery evidence and coverage is exported from
// one instance and imported into a second, empty instance; the imported scan
// must reproduce every occurrence and lifecycle detail, and re-exporting from
// the destination must equal the origin's bundle.
//
//	NSC_TEST_DATABASE_URL=postgres://... go test ./internal/store -run TestScanBundleRoundTripPostgres
func TestScanBundleRoundTripPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	origin := openIsolatedPostgres(t, ctx, dsn, "0039_schedule_name_uniqueness.sql")
	dest := openIsolatedPostgres(t, ctx, dsn, "0039_schedule_name_uniqueness.sql")

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
	policy, err := origin.CreateScanPolicy(ctx, ScanPolicy{
		Name:          "bundle-policy-" + suffix,
		TemplateSetID: templateSet.ID,
		RateLimit:     &rateLimit,
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
	if err := origin.SetScanCoverage(ctx, scanID, coverage, ""); err != nil {
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
		`INSERT INTO scan_policies (id, name, template_set_id, rate_limit, discovery_enabled) VALUES ($1, $2, $3, $4, COALESCE($5, TRUE))`,
		policy.ID, policy.Name, policy.TemplateSetID, policy.RateLimit, policy.DiscoveryEnabled); err != nil {
		t.Fatalf("mirror scan policy on destination: %v", err)
	}

	// Analyst overlays on the source lifecycle rows.
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
	if len(bundle.Findings) != 2 || len(bundle.Lifecycle) != 2 {
		t.Fatalf("bundle contents wrong: %d findings, %d lifecycle", len(bundle.Findings), len(bundle.Lifecycle))
	}
	if bundle.Config.TargetID != target.ID || bundle.Config.TemplateSetID != templateSet.ID || bundle.Config.ScanPolicyID != policy.ID {
		t.Fatalf("bundle config refs wrong: %+v", bundle.Config)
	}
	if bundle.Config.Target == nil || bundle.Config.TemplateSet == nil || bundle.Config.ScanPolicy == nil {
		t.Fatalf("bundle config snapshots missing")
	}

	// Import into the empty destination instance.
	result, err := dest.ImportScanBundle(ctx, bundle, ImportConflictError)
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
	if len(importedScan.CoveredEndpoints) != 2 {
		t.Fatalf("imported coverage lost: %v", importedScan.CoveredEndpoints)
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

	// Lifecycle: both rows, overlays carried, occurrence link + coverage evidence.
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
	if lcByTemplate["tpl-a"].Disposition != "accepted" {
		t.Fatalf("imported disposition wrong: %q", lcByTemplate["tpl-a"].Disposition)
	}
	if lcByTemplate["tpl-b"].RecastSeverity == nil || *lcByTemplate["tpl-b"].RecastSeverity != "critical" {
		t.Fatalf("imported recast wrong: %v", lcByTemplate["tpl-b"].RecastSeverity)
	}
	if lcByTemplate["tpl-a"].LastSeenScan == nil || *lcByTemplate["tpl-a"].LastSeenScan != scanID {
		t.Fatalf("last_covering_scan evidence missing after import: %v", lcByTemplate["tpl-a"].LastSeenScan)
	}

	// Re-export from the destination: the scan/findings/lifecycle must round-trip
	// exactly (config snapshots may differ only in that the refs resolved on the
	// origin instance — here both are the same ids since the destination is empty).
	reBundle, err := dest.ScanBundleForExport(ctx, scanID)
	if err != nil {
		t.Fatalf("re-export bundle: %v", err)
	}
	norm := func(b *types.ScanBundle) *types.ScanBundle {
		b.ExportedAt = time.Time{}
		return b
	}
	originJSON, _ := json.Marshal(norm(bundle))
	destJSON, _ := json.Marshal(norm(reBundle))
	if string(originJSON) != string(destJSON) {
		t.Fatalf("re-export diverges from origin bundle:\norigin: %s\ndest:   %s", originJSON, destJSON)
	}

	// Default conflict policy refuses to overwrite.
	if _, err := dest.ImportScanBundle(ctx, bundle, ImportConflictError); !errors.Is(err, ErrScanBundleConflict) {
		t.Fatalf("expected ErrScanBundleConflict, got %v", err)
	}
	// Duplicate policy mints a new id and keeps the original intact.
	dupResult, err := dest.ImportScanBundle(ctx, bundle, ImportConflictDuplicate)
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
	dest := openIsolatedPostgres(t, ctx, dsn, "0039_schedule_name_uniqueness.sql")

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
	// was still running, carrying a neutral disposition for the same finding.
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
		Lifecycle: []types.ScanBundleLifecycle{{
			TemplateID:  finding.TemplateID,
			MatchedAt:   finding.MatchedAt,
			Name:        finding.Info.Name,
			Severity:    finding.Info.Severity,
			Host:        finding.Host,
			Type:        finding.Type,
			EndpointKey: types.EndpointKey(finding.MatchedAt, finding.Type),
			FirstSeenAt: time.Now().UTC().Add(-2 * time.Hour),
			LastSeenAt:  time.Now().UTC().Add(-time.Hour),
			Disposition: "none",
		}},
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("test bundle fails validation: %v", err)
	}

	result, err := dest.ImportScanBundle(ctx, bundle, ImportConflictError)
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

	// The destination analyst's overlay must still win over the bundle's neutral
	// disposition, and the local occurrence count is now two.
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
