package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleBundle() ScanBundle {
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return ScanBundle{
		Format:        ScanBundleFormat,
		FormatVersion: ScanBundleFormatVersion,
		ExportedAt:    t0,
		Scan: ScanBundleScan{
			ID:                  NewID(),
			State:               string(ScanComplete),
			Source:              "adhoc",
			CreatedAt:           t0,
			FinishedAt:          &t0,
			TemplatesCommit:     "abc123",
			TemplateIDs:         []string{"cve-x"},
			SkippedFindingCount: 0,
			Spec:                json.RawMessage(`{"targets":["scanme.invalid"],"templates":{"template_ids":["cve-x"]}}`),
		},
		Findings: []ScanBundleFinding{{
			ID: 1, TemplateID: "cve-x", Name: "X", Severity: "high",
			Host: "scanme.invalid", MatchedAt: "https://scanme.invalid/", Type: "http",
			CreatedAt: t0, Raw: json.RawMessage(`{"template-id":"cve-x","host":"scanme.invalid"}`),
		}},
	}
}

func TestScanBundleValidate(t *testing.T) {
	base := sampleBundle()
	if err := base.Validate(); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
}

func TestScanBundleValidateRejects(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*ScanBundle)
		want   string
	}{
		{"wrong format", func(b *ScanBundle) { b.Format = "other/format" }, "unsupported"},
		{"future version", func(b *ScanBundle) { b.FormatVersion = ScanBundleFormatVersion + 1 }, "newer than this backend"},
		{"zero version", func(b *ScanBundle) { b.FormatVersion = 0 }, "invalid format_version"},
		{"missing scan id", func(b *ScanBundle) { b.Scan.ID = "" }, "scan.id is required"},
		{"non-uuid scan id", func(b *ScanBundle) { b.Scan.ID = "not-a-uuid" }, "not a UUID"},
		{"zero created at", func(b *ScanBundle) { b.Scan.CreatedAt = time.Time{} }, "scan.created_at is required"},
		{"future created at", func(b *ScanBundle) { b.Scan.CreatedAt = time.Now().Add(10 * time.Minute) }, "created_at is in the future"},
		{"future finished at", func(b *ScanBundle) {
			b.Scan.FinishedAt = timePtr(time.Now().Add(10 * time.Minute))
		}, "finished_at is in the future"},
		{"missing source", func(b *ScanBundle) { b.Scan.Source = "" }, "scan.source is required"},
		{"unknown state", func(b *ScanBundle) { b.Scan.State = "flying" }, "unknown scan state"},
		{"negative skipped count", func(b *ScanBundle) { b.Scan.SkippedFindingCount = -1 }, "cannot be negative"},
		{"missing spec", func(b *ScanBundle) { b.Scan.Spec = nil }, "spec is required"},
		{"invalid spec json", func(b *ScanBundle) { b.Scan.Spec = json.RawMessage(`{`) }, "valid JSON"},
		{"finding without template", func(b *ScanBundle) {
			b.Findings[0].TemplateID = ""
		}, "no template_id"},
		{"finding without created at", func(b *ScanBundle) {
			b.Findings[0].CreatedAt = time.Time{}
		}, "no created_at"},
		{"finding with broken raw", func(b *ScanBundle) {
			b.Findings[0].Raw = json.RawMessage(`not json`)
		}, "invalid or missing raw"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := sampleBundle()
			tc.mutate(&b)
			err := b.Validate()
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want containing %q", err, tc.want)
			}
		})
	}

	t.Run("nil bundle", func(t *testing.T) {
		var b *ScanBundle
		if err := b.Validate(); err == nil {
			t.Fatal("nil bundle must be rejected")
		}
	})
	t.Run("finding count cap", func(t *testing.T) {
		b := sampleBundle()
		b.Findings = make([]ScanBundleFinding, ScanBundleMaxFindings+1)
		if err := b.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("oversized finding list not rejected: %v", err)
		}
	})
	_ = t0
}

func timePtr(t time.Time) *time.Time { return &t }
