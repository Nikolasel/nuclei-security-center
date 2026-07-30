package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestTemplateAwareLifecyclePostgres exercises the complete lifecycle against a
// real migrated PostgreSQL database. It is intentionally opt-in so regular CI
// does not need to start external infrastructure:
//
//	NSC_TEST_DATABASE_URL=postgres://... go test ./internal/store -run TestTemplateAwareLifecyclePostgres
func TestTemplateAwareLifecyclePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn, "9999")

	suffix := types.NewID()
	target, err := st.CreateTarget(ctx, Target{
		Name:  "template-aware-lifecycle-" + suffix,
		Hosts: []string{"issue88.invalid"},
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	overlappingTarget, err := st.CreateTarget(ctx, Target{
		Name:  "template-aware-overlap-" + suffix,
		Hosts: []string{"issue88.invalid"},
	})
	if err != nil {
		t.Fatalf("create overlapping target: %v", err)
	}

	var scanIDs []string
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		for i := len(scanIDs) - 1; i >= 0; i-- {
			_, _, deleteErr := st.DeleteScan(cleanupCtx, scanIDs[i])
			if deleteErr != nil && !errors.Is(deleteErr, ErrNotFound) {
				t.Errorf("cleanup scan %s: %v", scanIDs[i], deleteErr)
			}
		}
		if deleteErr := st.DeleteTarget(cleanupCtx, target.ID); deleteErr != nil && !errors.Is(deleteErr, ErrNotFound) {
			t.Errorf("cleanup target: %v", deleteErr)
		}
		if deleteErr := st.DeleteTarget(cleanupCtx, overlappingTarget.ID); deleteErr != nil && !errors.Is(deleteErr, ErrNotFound) {
			t.Errorf("cleanup overlapping target: %v", deleteErr)
		}
	})

	createdAt := time.Now().UTC().Add(-time.Hour)
	createScanWithCoverage := func(coverage []types.EndpointCoverage, templateIDs []string, findingTemplates ...string) string {
		t.Helper()
		spec := types.ScanSpec{
			Targets: target.Hosts,
			Templates: types.TemplateSelector{
				TemplateIDs:     templateIDs,
				TemplatesCommit: "integration-test",
			},
		}
		scanID, createErr := st.CreateScan(ctx, spec, ScanLink{TargetID: target.ID})
		if createErr != nil {
			t.Fatalf("create scan: %v", createErr)
		}
		scanIDs = append(scanIDs, scanID)
		createdAt = createdAt.Add(time.Minute)
		if _, updateErr := st.pool.Exec(ctx,
			`UPDATE scans SET created_at = $2 WHERE id = $1`, scanID, createdAt); updateErr != nil {
			t.Fatalf("order scan: %v", updateErr)
		}
		for i, findingTemplate := range findingTemplates {
			matchedAt := "https://issue88.invalid"
			if i > 0 {
				matchedAt += "/path-" + strconv.Itoa(i)
			}
			finding := types.NucleiFinding{
				TemplateID: findingTemplate,
				Host:       "issue88.invalid",
				MatchedAt:  matchedAt,
				Type:       "http",
				Info: types.NucleiInfo{
					Name:     findingTemplate,
					Severity: "high",
				},
			}
			raw, marshalErr := json.Marshal(finding)
			if marshalErr != nil {
				t.Fatalf("marshal finding: %v", marshalErr)
			}
			if ingestErr := st.IngestFinding(ctx, scanID, target.ID, finding, raw); ingestErr != nil {
				t.Fatalf("ingest %s: %v", findingTemplate, ingestErr)
			}
		}
		if coverageErr := st.SetScanCoverage(ctx, scanID, coverage, ""); coverageErr != nil {
			t.Fatalf("set scan coverage: %v", coverageErr)
		}
		if completeErr := st.MarkComplete(ctx, scanID, "integration-test", "integration-test"); completeErr != nil {
			t.Fatalf("complete scan: %v", completeErr)
		}
		return scanID
	}
	createScan := func(templateIDs []string, findingTemplates ...string) string {
		coveredTemplates := append(append([]string{}, templateIDs...), findingTemplates...)
		seen := map[string]struct{}{}
		coverage := make([]types.EndpointCoverage, 0, len(coveredTemplates))
		for _, templateID := range coveredTemplates {
			if templateID == "" {
				continue
			}
			if _, exists := seen[templateID]; exists {
				continue
			}
			seen[templateID] = struct{}{}
			coverage = append(coverage, types.EndpointCoverage{
				TemplateID: templateID,
				Endpoint:   "issue88.invalid:443",
			})
		}
		return createScanWithCoverage(coverage, templateIDs, findingTemplates...)
	}

	createTLSScanRecord := func(scanTarget Target) string {
		t.Helper()
		spec := types.ScanSpec{
			Targets: scanTarget.Hosts,
			Templates: types.TemplateSelector{
				TemplateIDs:     []string{"tls-version"},
				TemplatesCommit: "integration-test",
			},
		}
		scanID, createErr := st.CreateScan(ctx, spec, ScanLink{TargetID: scanTarget.ID})
		if createErr != nil {
			t.Fatalf("create TLS scan: %v", createErr)
		}
		scanIDs = append(scanIDs, scanID)
		createdAt = createdAt.Add(time.Minute)
		if _, updateErr := st.pool.Exec(ctx,
			`UPDATE scans SET created_at = $2 WHERE id = $1`, scanID, createdAt); updateErr != nil {
			t.Fatalf("order TLS scan: %v", updateErr)
		}
		if coverageErr := st.SetScanCoverage(ctx, scanID, []types.EndpointCoverage{{
			TemplateID: "tls-version",
			Endpoint:   "issue88.invalid:443",
		}}, ""); coverageErr != nil {
			t.Fatalf("set TLS scan coverage: %v", coverageErr)
		}
		return scanID
	}
	ingestTLSVersions := func(scanTarget Target, scanID string, versions ...string) {
		t.Helper()
		for _, version := range versions {
			finding := types.NucleiFinding{
				TemplateID: "tls-version",
				Host:       "issue88.invalid",
				MatchedAt:  "issue88.invalid:443",
				Type:       "ssl",
				Info: types.NucleiInfo{
					Name:     "TLS version",
					Severity: "info",
				},
			}
			raw, marshalErr := json.Marshal(struct {
				types.NucleiFinding
				ExtractedResults []string `json:"extracted-results"`
			}{
				NucleiFinding:    finding,
				ExtractedResults: []string{version},
			})
			if marshalErr != nil {
				t.Fatalf("marshal TLS finding: %v", marshalErr)
			}
			if ingestErr := st.IngestFinding(ctx, scanID, scanTarget.ID, finding, raw); ingestErr != nil {
				t.Fatalf("ingest TLS %s: %v", version, ingestErr)
			}
		}
	}
	createTLSScanFor := func(scanTarget Target, versions ...string) string {
		t.Helper()
		scanID := createTLSScanRecord(scanTarget)
		ingestTLSVersions(scanTarget, scanID, versions...)
		if completeErr := st.MarkComplete(ctx, scanID, "integration-test", "integration-test"); completeErr != nil {
			t.Fatalf("complete TLS scan: %v", completeErr)
		}
		return scanID
	}
	createTLSScan := func(versions ...string) string {
		return createTLSScanFor(target, versions...)
	}

	assertFindingAt := func(templateID, matchedAt, wantState string, wantMitigated int) {
		t.Helper()
		query := FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
			Field: "target", Op: "any_of", Values: []string{target.ID},
		}}}}}
		rows, _, listErr := st.ListLifecycleFindings(ctx, query, 50, 0)
		if listErr != nil {
			t.Fatalf("list lifecycle: %v", listErr)
		}
		for _, row := range rows {
			if row.TemplateID != templateID || row.MatchedAt != matchedAt {
				continue
			}
			if row.DetectionState != wantState || row.TimesMitigated != wantMitigated {
				t.Fatalf("%s: state=%s times_mitigated=%d, want %s/%d",
					templateID, row.DetectionState, row.TimesMitigated, wantState, wantMitigated)
			}
			return
		}
		t.Fatalf("finding %s at %s not returned", templateID, matchedAt)
	}
	assertFinding := func(templateID, wantState string, wantMitigated int) {
		t.Helper()
		assertFindingAt(templateID, "https://issue88.invalid", wantState, wantMitigated)
	}

	createScan([]string{"template-a"}, "template-a")
	assertFinding("template-a", "new", 0)

	// A narrower scan cannot mitigate template-a.
	createScan([]string{"template-b"})
	assertFinding("template-a", "new", 0)

	// Template inclusion alone cannot mitigate template-a when Nuclei reached
	// only a different endpoint.
	createScanWithCoverage([]types.EndpointCoverage{{
		TemplateID: "template-a",
		Endpoint:   "other.invalid:443",
	}}, []string{"template-a"})
	assertFinding("template-a", "new", 0)

	// Reaching another service on the same host is not evidence that this
	// finding's endpoint was checked (the blocker raised in PR #153's review).
	createScanWithCoverage([]types.EndpointCoverage{{
		TemplateID: "template-a",
		Endpoint:   "issue88.invalid:8080",
	}}, []string{"template-a"})
	assertFinding("template-a", "new", 0)

	// Likewise, reaching the right endpoint with another template does not prove
	// that max-host-error did not skip template-a.
	createScanWithCoverage([]types.EndpointCoverage{{
		TemplateID: "template-b",
		Endpoint:   "issue88.invalid:443",
	}}, []string{"template-a", "template-b"})
	assertFinding("template-a", "new", 0)

	// Unknown legacy telemetry also fails closed rather than treating target-level
	// completion as endpoint evidence.
	createScanWithCoverage(nil, []string{"template-a"})
	assertFinding("template-a", "new", 0)

	// A scan that included template-a, reached its host, and did not observe the
	// result is real mitigation evidence.
	mitigationScan := createScan([]string{"template-a"})
	assertFinding("template-a", "mitigated", 0)

	createScan([]string{"template-a"}, "template-a")
	assertFinding("template-a", "resurfaced", 1)

	// Later unrelated coverage must not change the resurfaced state.
	createScan([]string{"template-b"})
	assertFinding("template-a", "resurfaced", 1)

	// Deleting the only mitigation evidence repairs the history using the same
	// template-aware rule.
	if _, _, err := st.DeleteScan(ctx, mitigationScan); err != nil {
		t.Fatalf("delete mitigation scan: %v", err)
	}
	assertFinding("template-a", "active", 0)

	// A pre-catalog occurrence proves scan-wide template coverage, not merely
	// coverage for its own lifecycle row. The second finding is therefore
	// mitigated when the next legacy scan observes the same template elsewhere.
	createScan(nil, "legacy-template", "legacy-template")
	createScan(nil, "legacy-template")
	assertFinding("legacy-template", "active", 0)
	assertFindingAt("legacy-template", "https://issue88.invalid/path-1", "mitigated", 0)

	// A legacy scan with neither concrete ids nor an occurrence proves nothing.
	createScan(nil)
	assertFindingAt("legacy-template", "https://issue88.invalid/path-1", "mitigated", 0)

	// When the second finding returns, its prior scan-wide absence is a real
	// mitigation cycle.
	createScan(nil, "legacy-template", "legacy-template")
	assertFindingAt("legacy-template", "https://issue88.invalid/path-1", "resurfaced", 1)

	// Malformed historical coverage is treated as unknown instead of either
	// becoming evidence or aborting scan-deletion repair.
	malformedScan := createScan(nil)
	if _, err := st.pool.Exec(ctx,
		`UPDATE scans SET covered_endpoints = '[42]'::jsonb WHERE id = $1`,
		malformedScan); err != nil {
		t.Fatalf("make malformed historical coverage: %v", err)
	}
	repairTrigger := createScan([]string{"template-a"}, "template-a")
	if _, _, err := st.DeleteScan(ctx, repairTrigger); err != nil {
		t.Fatalf("repair with malformed historical spec: %v", err)
	}

	// One template can intentionally emit multiple semantic results at the same
	// endpoint. They remain independently navigable and stable across scans.
	firstTLSScan := createTLSScan("tls12", "tls13")
	tlsOccurrences, total, err := st.ListFindings(ctx, FindingFilter{ScanID: firstTLSScan, Limit: 50})
	if err != nil {
		t.Fatalf("list TLS occurrences: %v", err)
	}
	if total != 2 || len(tlsOccurrences) != 2 {
		t.Fatalf("TLS occurrences = %d/%d, want 2/2", len(tlsOccurrences), total)
	}
	if tlsOccurrences[0].FindingID == nil || tlsOccurrences[1].FindingID == nil ||
		*tlsOccurrences[0].FindingID == *tlsOccurrences[1].FindingID {
		t.Fatalf("TLS variants did not split lifecycle ids: %#v", tlsOccurrences)
	}
	for _, occurrence := range tlsOccurrences {
		detail, detailErr := st.GetOccurrence(ctx, occurrence.ID)
		if detailErr != nil {
			t.Fatalf("get exact occurrence %d: %v", occurrence.ID, detailErr)
		}
		if detail.ID != occurrence.ID || detail.ScanID != firstTLSScan {
			t.Fatalf("exact occurrence metadata = %#v", detail)
		}
		var raw struct {
			ExtractedResults []string `json:"extracted-results"`
		}
		if unmarshalErr := json.Unmarshal(detail.Raw, &raw); unmarshalErr != nil ||
			len(raw.ExtractedResults) != 1 {
			t.Fatalf("exact occurrence raw = %s (%v)", detail.Raw, unmarshalErr)
		}
	}
	tlsQuery := FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "target", Op: "any_of", Values: []string{target.ID}},
		{Field: "name", Op: "contains", Values: []string{"tls-version"}},
	}}}}
	rawExport, err := st.ExportLifecycleRaw(ctx, tlsQuery)
	if err != nil {
		t.Fatalf("export TLS lifecycle raw: %v", err)
	}
	exportedVersions := map[string]bool{}
	for _, exported := range rawExport {
		var raw struct {
			ExtractedResults []string `json:"extracted-results"`
		}
		if unmarshalErr := json.Unmarshal(exported.Raw, &raw); unmarshalErr != nil ||
			len(raw.ExtractedResults) != 1 {
			t.Fatalf("decode exported TLS occurrence: %s (%v)", exported.Raw, unmarshalErr)
		}
		exportedVersions[raw.ExtractedResults[0]] = true
	}
	if len(rawExport) != 2 || !exportedVersions["tls12"] || !exportedVersions["tls13"] {
		t.Fatalf("raw lifecycle export = %#v, want both TLS variants", exportedVersions)
	}

	createTLSScan("tls12", "tls13")
	createTLSScan("tls13")
	rows, _, err := st.ListLifecycleFindings(ctx, FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
		Field: "target", Op: "any_of", Values: []string{target.ID},
	}}}}}, 500, 0)
	if err != nil {
		t.Fatalf("list TLS lifecycle: %v", err)
	}
	tlsStates := map[string]string{}
	for _, row := range rows {
		if row.TemplateID != "tls-version" {
			continue
		}
		detail, detailErr := st.GetLifecycleFinding(ctx, row.ID)
		if detailErr != nil {
			t.Fatalf("get TLS lifecycle %d: %v", row.ID, detailErr)
		}
		var raw struct {
			ExtractedResults []string `json:"extracted-results"`
		}
		if unmarshalErr := json.Unmarshal(detail.Raw, &raw); unmarshalErr != nil {
			t.Fatalf("decode TLS lifecycle %d: %v", row.ID, unmarshalErr)
		}
		if len(raw.ExtractedResults) != 1 {
			t.Fatalf("TLS lifecycle %d results = %#v", row.ID, raw.ExtractedResults)
		}
		tlsStates[raw.ExtractedResults[0]] = row.DetectionState
	}
	if tlsStates["tls12"] != "mitigated" || tlsStates["tls13"] != "active" {
		t.Fatalf("TLS lifecycle states = %#v, want tls12 mitigated / tls13 active", tlsStates)
	}

	// Target records are provenance, not lifecycle identity. The same concrete
	// TLS 1.3 result from an overlapping target joins the existing global row.
	overlapScan := createTLSScanFor(overlappingTarget, "tls13")
	overlapOccurrences, total, err := st.ListFindings(ctx, FindingFilter{ScanID: overlapScan, Limit: 50})
	if err != nil || total != 1 || len(overlapOccurrences) != 1 ||
		overlapOccurrences[0].FindingID == nil {
		t.Fatalf("overlap occurrences = %#v total=%d err=%v", overlapOccurrences, total, err)
	}
	var tls13LifecycleID int64
	for _, row := range rows {
		if row.TemplateID == "tls-version" {
			detail, detailErr := st.GetLifecycleFinding(ctx, row.ID)
			if detailErr != nil {
				t.Fatalf("get candidate TLS lifecycle: %v", detailErr)
			}
			var raw struct {
				ExtractedResults []string `json:"extracted-results"`
			}
			if unmarshalErr := json.Unmarshal(detail.Raw, &raw); unmarshalErr == nil &&
				len(raw.ExtractedResults) == 1 && raw.ExtractedResults[0] == "tls13" {
				tls13LifecycleID = row.ID
				break
			}
		}
	}
	if *overlapOccurrences[0].FindingID != tls13LifecycleID {
		t.Fatalf("overlap lifecycle = %d, want existing TLS 1.3 lifecycle %d",
			*overlapOccurrences[0].FindingID, tls13LifecycleID)
	}
	detail, err := st.GetLifecycleFinding(ctx, tls13LifecycleID)
	if err != nil {
		t.Fatalf("get globally merged TLS 1.3 detail: %v", err)
	}
	if fmt.Sprint(detail.TargetIDs) != fmt.Sprint(sortedStrings(target.ID, overlappingTarget.ID)) {
		t.Fatalf("globally merged targets = %v, want both target records", detail.TargetIDs)
	}

	// A slower, older scan finishing after a newer overlapping scan must not
	// move last_seen backwards or manufacture a mitigation/resurface cycle.
	olderScan := createTLSScanRecord(target)
	newerScan := createTLSScanRecord(overlappingTarget)
	ingestTLSVersions(overlappingTarget, newerScan, "tls11")
	if err := st.MarkComplete(ctx, newerScan, "integration-test", "integration-test"); err != nil {
		t.Fatalf("complete newer overlapping scan: %v", err)
	}
	ingestTLSVersions(target, olderScan, "tls11")
	if err := st.MarkComplete(ctx, olderScan, "integration-test", "integration-test"); err != nil {
		t.Fatalf("complete older overlapping scan: %v", err)
	}
	var lastSeen, lastCovering string
	var timesMitigated int
	var detectionState string
	if err := st.pool.QueryRow(ctx,
		`SELECT last_seen_scan, last_covering_scan, times_mitigated, `+lcDetectionExpr+`
		   FROM finding_lifecycle l
		  WHERE template_id = 'tls-version'
		    AND result_discriminator = $1`,
		mustResultDiscriminator(t, `{"extracted-results":["tls11"]}`),
	).Scan(&lastSeen, &lastCovering, &timesMitigated, &detectionState); err != nil {
		t.Fatalf("read out-of-order lifecycle: %v", err)
	}
	if lastSeen != newerScan || lastCovering != newerScan || timesMitigated != 0 || detectionState != "active" {
		t.Fatalf("out-of-order lifecycle = seen:%s covering:%s mitigated:%d state:%s, want newer/newer/0/active",
			lastSeen, lastCovering, timesMitigated, detectionState)
	}

	// Chronology is observed, observed, absent even though the absent scan
	// completes before the second observation is ingested. The late observation
	// predates the coverage gap, so it must not count as a resurfacing.
	createTLSScanFor(target, "tls10")
	lateObservedScan := createTLSScanRecord(target)
	newerAbsentScan := createTLSScanRecord(target)
	if err := st.MarkComplete(ctx, newerAbsentScan, "integration-test", "integration-test"); err != nil {
		t.Fatalf("complete newer absent scan: %v", err)
	}
	ingestTLSVersions(target, lateObservedScan, "tls10")
	if err := st.MarkComplete(ctx, lateObservedScan, "integration-test", "integration-test"); err != nil {
		t.Fatalf("complete late older observation: %v", err)
	}
	if err := st.pool.QueryRow(ctx,
		`SELECT last_seen_scan, last_covering_scan, times_mitigated, `+lcDetectionExpr+`
		   FROM finding_lifecycle l
		  WHERE template_id = 'tls-version'
		    AND result_discriminator = $1`,
		mustResultDiscriminator(t, `{"extracted-results":["tls10"]}`),
	).Scan(&lastSeen, &lastCovering, &timesMitigated, &detectionState); err != nil {
		t.Fatalf("read late observation before absence: %v", err)
	}
	if lastSeen != lateObservedScan || lastCovering != newerAbsentScan ||
		timesMitigated != 0 || detectionState != "mitigated" {
		t.Fatalf("late observation lifecycle = seen:%s covering:%s mitigated:%d state:%s, want older/newer/0/mitigated",
			lastSeen, lastCovering, timesMitigated, detectionState)
	}
}

func sortedStrings(values ...string) []string {
	sort.Strings(values)
	return values
}

func mustResultDiscriminator(t *testing.T, raw string) string {
	t.Helper()
	discriminator, err := resultDiscriminator([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return discriminator
}
