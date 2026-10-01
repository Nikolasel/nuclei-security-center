package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestScanDigestBucketsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	target, err := st.CreateTarget(ctx, Target{
		Name:  "digest-" + types.NewID(),
		Hosts: []string{"digest.invalid"},
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	createdAt := time.Now().UTC().Add(-time.Hour)
	nextScan := func(templateIDs []string, findings []types.NucleiFinding, coverage []types.EndpointCoverage) string {
		t.Helper()
		scanID, createErr := st.CreateScan(ctx, types.ScanSpec{
			Targets: target.Hosts,
			Templates: types.TemplateSelector{
				TemplateIDs:     templateIDs,
				TemplatesCommit: "digest-test",
			},
		}, ScanLink{TargetID: target.ID})
		if createErr != nil {
			t.Fatalf("create scan: %v", createErr)
		}
		createdAt = createdAt.Add(time.Minute)
		if _, updateErr := st.pool.Exec(ctx, `UPDATE scans SET created_at = $2 WHERE id = $1`, scanID, createdAt); updateErr != nil {
			t.Fatalf("order scan: %v", updateErr)
		}
		for _, finding := range findings {
			raw, marshalErr := json.Marshal(finding)
			if marshalErr != nil {
				t.Fatalf("marshal: %v", marshalErr)
			}
			if ingestErr := st.IngestFinding(ctx, scanID, target.ID, finding, raw); ingestErr != nil {
				t.Fatalf("ingest: %v", ingestErr)
			}
		}
		if coverageErr := st.SetScanCoverage(ctx, scanID, coverage, ""); coverageErr != nil {
			t.Fatalf("coverage: %v", coverageErr)
		}
		if completeErr := st.MarkComplete(ctx, scanID, "digest-test", "digest-test"); completeErr != nil {
			t.Fatalf("complete: %v", completeErr)
		}
		return scanID
	}
	endpoint := []types.EndpointCoverage{{TemplateID: "tpl-a", Endpoint: "digest.invalid:443"}}
	finding := func(sev string) types.NucleiFinding {
		return types.NucleiFinding{
			TemplateID: "tpl-a",
			Host:       "digest.invalid",
			MatchedAt:  "https://digest.invalid",
			Type:       "http",
			Info:       types.NucleiInfo{Name: "A", Severity: sev},
		}
	}

	first := nextScan([]string{"tpl-a"}, []types.NucleiFinding{finding("critical")}, endpoint)
	p := mustClaimDigest(t, ctx, st, first)
	if p.New.Critical != 1 || p.Changed.Total() != 0 || p.Fixed.Total() != 0 {
		t.Fatalf("first scan digest = %+v, want 1 new critical", p)
	}
	if len(p.Findings) != 1 || p.Findings[0].Status != "new" {
		t.Fatalf("first findings = %+v", p.Findings)
	}

	// Same finding still present: active, no mail delta.
	second := nextScan([]string{"tpl-a"}, []types.NucleiFinding{finding("critical")}, endpoint)
	p = mustClaimDigest(t, ctx, st, second)
	if p.HasDelta() {
		t.Fatalf("active re-observation must not mail, got %+v", p)
	}

	// Disappears with proven coverage: Fixed once.
	third := nextScan([]string{"tpl-a"}, nil, endpoint)
	p = mustClaimDigest(t, ctx, st, third)
	if p.Fixed.Critical != 1 || p.New.Total() != 0 || p.Changed.Total() != 0 {
		t.Fatalf("mitigation digest = %+v, want 1 fixed critical", p)
	}

	// Still gone: must not re-announce Fixed.
	fourth := nextScan([]string{"tpl-a"}, nil, endpoint)
	p = mustClaimDigest(t, ctx, st, fourth)
	if p.HasDelta() {
		t.Fatalf("repeat mitigation must stay silent, got %+v", p)
	}

	// Resurface: Changed, not New.
	fifth := nextScan([]string{"tpl-a"}, []types.NucleiFinding{finding("critical")}, endpoint)
	p = mustClaimDigest(t, ctx, st, fifth)
	if p.Changed.Critical != 1 || p.New.Total() != 0 {
		t.Fatalf("resurface digest = %+v, want 1 changed critical", p)
	}

	// Unproven coverage cannot produce Fixed.
	sixth := nextScan([]string{"tpl-a"}, nil, nil)
	p = mustClaimDigest(t, ctx, st, sixth)
	if p.Fixed.Total() != 0 {
		t.Fatalf("unproven coverage mailed Fixed: %+v", p)
	}

	// Live false-positive is excluded from New.
	fpScan, err := st.CreateScan(ctx, types.ScanSpec{
		Targets:   target.Hosts,
		Templates: types.TemplateSelector{TemplateIDs: []string{"tpl-b"}, TemplatesCommit: "digest-test"},
	}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create fp scan: %v", err)
	}
	createdAt = createdAt.Add(time.Minute)
	if _, err := st.pool.Exec(ctx, `UPDATE scans SET created_at = $2 WHERE id = $1`, fpScan, createdAt); err != nil {
		t.Fatalf("order fp scan: %v", err)
	}
	fpFinding := types.NucleiFinding{
		TemplateID: "tpl-b",
		Host:       "digest.invalid",
		MatchedAt:  "https://digest.invalid/b",
		Type:       "http",
		Info:       types.NucleiInfo{Name: "B", Severity: "high"},
	}
	raw, _ := json.Marshal(fpFinding)
	if err := st.IngestFinding(ctx, fpScan, target.ID, fpFinding, raw); err != nil {
		t.Fatalf("ingest fp: %v", err)
	}
	rows, _, err := st.ListLifecycleFindings(ctx, FindingQuery{}, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var fpID int64
	for _, row := range rows {
		if row.TemplateID == "tpl-b" {
			fpID = row.ID
		}
	}
	if fpID == 0 {
		t.Fatal("tpl-b not found")
	}
	if err := st.SetDisposition(ctx, fpID, "false_positive", "noise", "tester", nil); err != nil {
		t.Fatalf("set fp: %v", err)
	}
	if err := st.SetScanCoverage(ctx, fpScan, []types.EndpointCoverage{{TemplateID: "tpl-b", Endpoint: "digest.invalid:443"}}, ""); err != nil {
		t.Fatalf("fp coverage: %v", err)
	}
	if err := st.MarkComplete(ctx, fpScan, "digest-test", "digest-test"); err != nil {
		t.Fatalf("complete fp: %v", err)
	}
	p = mustClaimDigest(t, ctx, st, fpScan)
	if p.New.High != 0 {
		t.Fatalf("false positive mailed as New: %+v", p)
	}

	// Failed scan records a failed outbox row; cancelled does not.
	failID, err := st.CreateScan(ctx, types.ScanSpec{
		Targets:   target.Hosts,
		Templates: types.TemplateSelector{TemplateIDs: []string{"tpl-a"}, TemplatesCommit: "digest-test"},
	}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create fail scan: %v", err)
	}
	if err := st.MarkFailed(ctx, failID, "node exploded", "", ""); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	rawFail, ok, err := st.ClaimScanNotification(ctx, failID, NotifyKindFailed)
	if err != nil || !ok {
		t.Fatalf("claim failed: ok=%v err=%v", ok, err)
	}
	fp, err := ParseScanFailedPayload(rawFail)
	if err != nil || fp.Reason != "node exploded" {
		t.Fatalf("failed payload = %+v err=%v", fp, err)
	}
	rawFail, ok, err = st.ClaimScanNotification(ctx, failID, NotifyKindFailed)
	if err != nil || ok {
		t.Fatalf("second failed claim must be denied, ok=%v err=%v raw=%s", ok, err, rawFail)
	}

	cancelID, err := st.CreateScan(ctx, types.ScanSpec{
		Targets:   target.Hosts,
		Templates: types.TemplateSelector{TemplateIDs: []string{"tpl-a"}, TemplatesCommit: "digest-test"},
	}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create cancel scan: %v", err)
	}
	if _, cancelled, err := st.CancelScan(ctx, cancelID, "operator"); err != nil || !cancelled {
		t.Fatalf("cancel: cancelled=%v err=%v", cancelled, err)
	}
	if err := st.MarkFailed(ctx, cancelID, "node aborted", "", ""); err != nil {
		t.Fatalf("mark failed after cancel: %v", err)
	}
	if _, ok, err := st.ClaimScanNotification(ctx, cancelID, NotifyKindFailed); err != nil || ok {
		t.Fatalf("cancelled scan must not notify, ok=%v err=%v", ok, err)
	}

	// Completing twice does not insert a second digest.
	if err := st.MarkComplete(ctx, first, "digest-test", "digest-test"); err != nil {
		t.Fatalf("repeat complete: %v", err)
	}
	if _, ok, err := st.ClaimScanNotification(ctx, first, NotifyKindDigest); err != nil || ok {
		t.Fatalf("repeat complete must not yield a new unclaimed digest, ok=%v err=%v", ok, err)
	}

	// Nuclei unknown and any other non-standard severity are their own bucket.
	unknownScan := nextScan([]string{"tpl-unknown"}, []types.NucleiFinding{{
		TemplateID: "tpl-unknown",
		Host:       "digest.invalid",
		MatchedAt:  "https://digest.invalid/unknown",
		Type:       "http",
		Info:       types.NucleiInfo{Name: "U", Severity: "unknown"},
	}}, []types.EndpointCoverage{{TemplateID: "tpl-unknown", Endpoint: "digest.invalid:443"}})
	p = mustClaimDigest(t, ctx, st, unknownScan)
	if p.New.Unknown != 1 || p.New.Info != 0 {
		t.Fatalf("unknown severity digest = %+v, want 1 new unknown", p)
	}
	otherScan := nextScan([]string{"tpl-other"}, []types.NucleiFinding{{
		TemplateID: "tpl-other",
		Host:       "digest.invalid",
		MatchedAt:  "https://digest.invalid/other",
		Type:       "http",
		Info:       types.NucleiInfo{Name: "O", Severity: "not-a-severity"},
	}}, []types.EndpointCoverage{{TemplateID: "tpl-other", Endpoint: "digest.invalid:443"}})
	p = mustClaimDigest(t, ctx, st, otherScan)
	if p.New.Unknown != 1 || p.New.Info != 0 {
		t.Fatalf("non-standard severity digest = %+v, want 1 new unknown", p)
	}

	// A failed scan that ingested the finding moves last_seen_scan without
	// advancing last_covering_scan; the next covering absence is still Fixed.
	failedPartial, err := st.CreateScan(ctx, types.ScanSpec{
		Targets:   target.Hosts,
		Templates: types.TemplateSelector{TemplateIDs: []string{"tpl-a"}, TemplatesCommit: "digest-test"},
	}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create partial fail scan: %v", err)
	}
	createdAt = createdAt.Add(time.Minute)
	if _, err := st.pool.Exec(ctx, `UPDATE scans SET created_at = $2 WHERE id = $1`, failedPartial, createdAt); err != nil {
		t.Fatalf("order partial fail scan: %v", err)
	}
	rawPartial, _ := json.Marshal(finding("critical"))
	if err := st.IngestFinding(ctx, failedPartial, target.ID, finding("critical"), rawPartial); err != nil {
		t.Fatalf("ingest partial fail: %v", err)
	}
	if err := st.MarkFailed(ctx, failedPartial, "node died mid-ingest", "", ""); err != nil {
		t.Fatalf("mark partial fail: %v", err)
	}
	if _, ok, err := st.ClaimScanNotification(ctx, failedPartial, NotifyKindFailed); err != nil || !ok {
		t.Fatalf("claim partial fail: ok=%v err=%v", ok, err)
	}
	absenceAfterFail := nextScan([]string{"tpl-a"}, nil, endpoint)
	p = mustClaimDigest(t, ctx, st, absenceAfterFail)
	if p.Fixed.Critical != 1 || p.New.Total() != 0 || p.Changed.Total() != 0 {
		t.Fatalf("absence after failed partial ingest = %+v, want 1 fixed critical", p)
	}

	// Startup orphan sweep writes a failed outbox row; claimed rows stay claimed.
	orphanID, err := st.CreateScan(ctx, types.ScanSpec{
		Targets:   target.Hosts,
		Templates: types.TemplateSelector{TemplateIDs: []string{"tpl-a"}, TemplatesCommit: "digest-test"},
	}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create orphan scan: %v", err)
	}
	n, err := st.FailOrphanedScans(ctx, "orphaned: backend restarted while scan was in progress")
	if err != nil || n != 1 {
		t.Fatalf("FailOrphanedScans = %d, %v want 1, nil", n, err)
	}
	rawFail, ok, err = st.ClaimScanNotification(ctx, orphanID, NotifyKindFailed)
	if err != nil || !ok {
		t.Fatalf("claim orphan failed: ok=%v err=%v", ok, err)
	}
	fp, err = ParseScanFailedPayload(rawFail)
	if err != nil || fp.Reason != "orphaned: backend restarted while scan was in progress" {
		t.Fatalf("orphan payload = %+v err=%v", fp, err)
	}
	pending, err := st.ListUnclaimedScanNotifications(ctx)
	if err != nil {
		t.Fatalf("list unclaimed: %v", err)
	}
	for _, ref := range pending {
		if ref.ScanID == orphanID {
			t.Fatalf("claimed orphan still listed: %+v", pending)
		}
	}
	queuedAgain, err := st.CreateScan(ctx, types.ScanSpec{
		Targets:   target.Hosts,
		Templates: types.TemplateSelector{TemplateIDs: []string{"tpl-a"}, TemplatesCommit: "digest-test"},
	}, ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create second orphan: %v", err)
	}
	if _, err := st.FailOrphanedScans(ctx, "orphaned again"); err != nil {
		t.Fatalf("second FailOrphanedScans: %v", err)
	}
	pending, err = st.ListUnclaimedScanNotifications(ctx)
	if err != nil {
		t.Fatalf("list unclaimed after second orphan: %v", err)
	}
	foundQueued := false
	for _, ref := range pending {
		if ref.ScanID == queuedAgain && ref.Kind == NotifyKindFailed {
			foundQueued = true
		}
		if ref.ScanID == orphanID {
			t.Fatalf("already-claimed orphan listed after later sweep: %+v", pending)
		}
	}
	if !foundQueued {
		t.Fatalf("unclaimed orphan missing from list: %+v", pending)
	}
}

func TestScanDigestMinSeverityPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	target, err := st.CreateTarget(ctx, Target{
		Name:  "digest-floor-" + types.NewID(),
		Hosts: []string{"digest-floor.invalid"},
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	complete := func(link ScanLink, sev, templateID string) string {
		t.Helper()
		scanID, createErr := st.CreateScan(ctx, types.ScanSpec{
			Targets:   target.Hosts,
			Templates: types.TemplateSelector{TemplateIDs: []string{templateID}, TemplatesCommit: "digest-test"},
		}, link)
		if createErr != nil {
			t.Fatalf("create scan: %v", createErr)
		}
		finding := types.NucleiFinding{
			TemplateID: templateID,
			Host:       "digest-floor.invalid",
			MatchedAt:  "https://digest-floor.invalid/" + templateID,
			Type:       "http",
			Info:       types.NucleiInfo{Name: sev, Severity: sev},
		}
		raw, _ := json.Marshal(finding)
		if ingestErr := st.IngestFinding(ctx, scanID, target.ID, finding, raw); ingestErr != nil {
			t.Fatalf("ingest: %v", ingestErr)
		}
		if coverageErr := st.SetScanCoverage(ctx, scanID, []types.EndpointCoverage{{TemplateID: templateID, Endpoint: "digest-floor.invalid:443"}}, ""); coverageErr != nil {
			t.Fatalf("coverage: %v", coverageErr)
		}
		if completeErr := st.MarkComplete(ctx, scanID, "digest-test", "digest-test"); completeErr != nil {
			t.Fatalf("complete: %v", completeErr)
		}
		return scanID
	}

	infoScan := complete(ScanLink{TargetID: target.ID, NotifyMinSeverity: "low"}, "info", "tpl-floor-info")
	p := mustClaimDigest(t, ctx, st, infoScan)
	if p.HasDelta() || len(p.Findings) != 0 {
		t.Fatalf("info-only delta with min=low must be empty, got %+v", p)
	}

	highScan := complete(ScanLink{TargetID: target.ID, NotifyMinSeverity: "low"}, "high", "tpl-floor-high")
	p = mustClaimDigest(t, ctx, st, highScan)
	if p.New.High != 1 || p.New.Info != 0 || len(p.Findings) != 1 {
		t.Fatalf("high finding with min=low = %+v", p)
	}

	unknownScan := complete(ScanLink{TargetID: target.ID, NotifyMinSeverity: "low"}, "not-a-severity", "tpl-floor-unknown")
	p = mustClaimDigest(t, ctx, st, unknownScan)
	if p.New.Unknown != 1 {
		t.Fatalf("unknown severity must still mail at min=low, got %+v", p)
	}

	muted := false
	mutedScan := complete(ScanLink{TargetID: target.ID, NotifyDigestEnabled: &muted}, "critical", "tpl-floor-muted")
	row, err := st.GetScan(ctx, mutedScan)
	if err != nil {
		t.Fatalf("get muted scan: %v", err)
	}
	if row.NotifyDigestEnabled {
		t.Fatal("muted scan must snapshot notify_digest_enabled=false")
	}
	p = mustClaimDigest(t, ctx, st, mutedScan)
	if p.New.Critical != 1 {
		t.Fatalf("muted scan still records a digest payload, got %+v", p)
	}
}

func mustClaimDigest(t *testing.T, ctx context.Context, st *Store, scanID string) ScanDigestPayload {
	t.Helper()
	raw, ok, err := st.ClaimScanNotification(ctx, scanID, NotifyKindDigest)
	if err != nil {
		t.Fatalf("claim digest %s: %v", scanID, err)
	}
	if !ok {
		t.Fatalf("claim digest %s: missing outbox row", scanID)
	}
	p, err := ParseScanDigestPayload(raw)
	if err != nil {
		t.Fatalf("parse digest %s: %v", scanID, err)
	}
	return p
}
