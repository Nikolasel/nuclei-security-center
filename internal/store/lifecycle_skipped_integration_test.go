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

// TestSkippedFindingDoesNotMitigatePostgres verifies that incomplete result
// ingest cannot turn an absent finding into negative evidence, including when
// lifecycle history is rebuilt after deleting a later positive observation.
func TestSkippedFindingDoesNotMitigatePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	target, err := st.CreateTarget(ctx, Target{
		Name:  "skipped-finding-lifecycle-" + types.NewID(),
		Hosts: []string{"skip.invalid"},
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
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
	})

	createdAt := time.Now().UTC().Add(-4 * time.Minute)
	createScan := func(withFinding bool, skippedCount int) string {
		t.Helper()
		spec := types.ScanSpec{
			Targets: target.Hosts,
			Templates: types.TemplateSelector{
				TemplateIDs:     []string{"skipped-template"},
				TemplatesCommit: "integration-test",
			},
		}
		scanID, createErr := st.CreateScan(ctx, spec, ScanLink{TargetID: target.ID})
		if createErr != nil {
			t.Fatalf("create scan: %v", createErr)
		}
		scanIDs = append(scanIDs, scanID)
		createdAt = createdAt.Add(time.Minute)
		if _, updateErr := st.pool.Exec(ctx, `UPDATE scans SET created_at = $2 WHERE id = $1`, scanID, createdAt); updateErr != nil {
			t.Fatalf("order scan: %v", updateErr)
		}

		if withFinding {
			finding := types.NucleiFinding{
				TemplateID: "skipped-template",
				Host:       "skip.invalid",
				MatchedAt:  "https://skip.invalid",
				Type:       "http",
				Info: types.NucleiInfo{
					Name:     "Skipped ingest lifecycle test",
					Severity: "high",
				},
			}
			raw, marshalErr := json.Marshal(finding)
			if marshalErr != nil {
				t.Fatalf("marshal finding: %v", marshalErr)
			}
			if ingestErr := st.IngestFinding(ctx, scanID, target.ID, finding, raw); ingestErr != nil {
				t.Fatalf("ingest finding: %v", ingestErr)
			}
		}
		if coverageErr := st.SetScanCoverage(ctx, scanID, []types.EndpointCoverage{{
			TemplateID: "skipped-template",
			Endpoint:   "skip.invalid:443",
		}}, ""); coverageErr != nil {
			t.Fatalf("set scan coverage: %v", coverageErr)
		}
		if skippedCount > 0 {
			if countErr := st.SetScanSkippedFindingCount(ctx, scanID, skippedCount); countErr != nil {
				t.Fatalf("set skipped finding count: %v", countErr)
			}
		}
		if completeErr := st.MarkComplete(ctx, scanID, "integration-test", "integration-test"); completeErr != nil {
			t.Fatalf("complete scan: %v", completeErr)
		}
		return scanID
	}

	assertState := func(want string) {
		t.Helper()
		rows, total, listErr := st.ListLifecycleFindings(ctx, FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
			Field: "target", Op: "any_of", Values: []string{target.ID},
		}}}}}, 50, 0)
		if listErr != nil {
			t.Fatalf("list lifecycle: %v", listErr)
		}
		if total != 1 || len(rows) != 1 {
			t.Fatalf("lifecycle rows = %d/%d, want one", len(rows), total)
		}
		if rows[0].DetectionState != want {
			t.Fatalf("detection state = %q, want %q", rows[0].DetectionState, want)
		}
	}

	createScan(true, 0)
	assertState("new")

	skippedScan := createScan(false, 1)
	assertState("new")
	scanRow, getErr := st.GetScan(ctx, skippedScan)
	if getErr != nil {
		t.Fatalf("get skipped scan: %v", getErr)
	}
	if scanRow.SkippedFindingCount != 1 {
		t.Fatalf("skipped finding count = %d, want 1", scanRow.SkippedFindingCount)
	}

	// Exact observations remain positive evidence even when the same scan also
	// skipped another source record.
	positiveScan := createScan(true, 1)
	assertState("active")
	if _, _, deleteErr := st.DeleteScan(ctx, positiveScan); deleteErr != nil {
		t.Fatalf("delete later positive scan: %v", deleteErr)
	}
	scanIDs = scanIDs[:2]
	assertState("new")
}
