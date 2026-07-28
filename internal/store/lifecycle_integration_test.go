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

// TestTemplateAwareLifecyclePostgres exercises the complete lifecycle against a
// real migrated PostgreSQL database. It is opt-in so ordinary unit tests need no
// external service:
//
//	NSC_TEST_DATABASE_URL=postgres://... go test ./internal/store -run TestTemplateAwareLifecyclePostgres
func TestTemplateAwareLifecyclePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	suffix := types.NewID()
	target, err := st.CreateTarget(ctx, Target{
		Name:  "template-aware-lifecycle-" + suffix,
		Hosts: []string{"issue88.invalid"},
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

	createdAt := time.Now().UTC().Add(-time.Hour)
	createScan := func(templateIDs []string, findingTemplate string) string {
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
		if findingTemplate != "" {
			finding := types.NucleiFinding{
				TemplateID: findingTemplate,
				Host:       "issue88.invalid",
				MatchedAt:  "https://issue88.invalid",
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
		if completeErr := st.MarkComplete(ctx, scanID, "integration-test", "integration-test"); completeErr != nil {
			t.Fatalf("complete scan: %v", completeErr)
		}
		return scanID
	}

	assertFinding := func(templateID, wantState string, wantMitigated int) {
		t.Helper()
		query := FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
			Field: "target", Op: "any_of", Values: []string{target.ID},
		}}}}}
		rows, _, listErr := st.ListLifecycleFindings(ctx, query, 50, 0)
		if listErr != nil {
			t.Fatalf("list lifecycle: %v", listErr)
		}
		for _, row := range rows {
			if row.TemplateID != templateID {
				continue
			}
			if row.DetectionState != wantState || row.TimesMitigated != wantMitigated {
				t.Fatalf("%s: state=%s times_mitigated=%d, want %s/%d",
					templateID, row.DetectionState, row.TimesMitigated, wantState, wantMitigated)
			}
			return
		}
		t.Fatalf("finding %s not returned", templateID)
	}

	createScan([]string{"template-a"}, "template-a")
	assertFinding("template-a", "new", 0)

	// A narrower scan cannot mitigate template-a.
	createScan([]string{"template-b"}, "")
	assertFinding("template-a", "new", 0)

	// A scan that did include template-a and did not observe it is real
	// mitigation evidence.
	mitigationScan := createScan([]string{"template-a"}, "")
	assertFinding("template-a", "mitigated", 0)

	createScan([]string{"template-a"}, "template-a")
	assertFinding("template-a", "resurfaced", 1)

	// Later unrelated coverage must not change the resurfaced state.
	createScan([]string{"template-b"}, "")
	assertFinding("template-a", "resurfaced", 1)

	// Deleting the only mitigation evidence repairs the history using the same
	// template-aware rule.
	if _, _, err := st.DeleteScan(ctx, mitigationScan); err != nil {
		t.Fatalf("delete mitigation scan: %v", err)
	}
	assertFinding("template-a", "active", 0)

	// Pre-catalog occurrences prove positive coverage, but a legacy scan with no
	// ids and no occurrence cannot manufacture a mitigation cycle.
	createScan(nil, "legacy-template")
	createScan(nil, "")
	createScan(nil, "legacy-template")
	assertFinding("legacy-template", "active", 0)
}
