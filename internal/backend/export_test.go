package backend

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func sampleRows() []store.LifecycleRow {
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return []store.LifecycleRow{
		{
			TemplateID: "cve-2021-1234", Name: "Example RCE", Severity: "high",
			EffectiveSeverity: "high", Host: "scanme.sh", MatchedAt: "https://scanme.sh/x",
			Type: "http", CVE: []string{"CVE-2021-1234"}, Tags: []string{"cve", "rce"},
			Disposition: "none", DetectionState: "active", EffectiveState: "active",
			TimesMitigated: 0, FirstSeenAt: t0, LastSeenAt: t0,
		},
		{
			// Same template id → should collapse to one SARIF rule.
			TemplateID: "cve-2021-1234", Name: "Example RCE", Severity: "high",
			EffectiveSeverity: "critical", Host: "other.sh", MatchedAt: "",
			Type: "http", Disposition: "accepted", DetectionState: "active",
			EffectiveState: "accepted", FirstSeenAt: t0, LastSeenAt: t0,
		},
	}
}

func TestSarifLevel(t *testing.T) {
	cases := map[string]string{
		"critical": "error", "high": "error", "medium": "warning",
		"low": "note", "info": "note", "": "note", "bogus": "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestWriteFindingsCSV(t *testing.T) {
	var buf bytes.Buffer
	writeFindingsCSV(&buf, sampleRows())

	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(recs) != 3 { // header + 2 rows
		t.Fatalf("got %d records, want 3", len(recs))
	}
	if recs[0][0] != "template_id" || recs[0][11] != "cve" {
		t.Errorf("unexpected header: %v", recs[0])
	}
	if recs[1][0] != "cve-2021-1234" || recs[1][11] != "CVE-2021-1234" {
		t.Errorf("unexpected first row: %v", recs[1])
	}
	// tags joined with ";"
	if recs[1][12] != "cve;rce" {
		t.Errorf("tags = %q, want %q", recs[1][12], "cve;rce")
	}
}

func TestWriteFindingsSARIF(t *testing.T) {
	var buf bytes.Buffer
	writeFindingsSARIF(&buf, sampleRows())

	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("sarif is not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("bad sarif envelope: version=%q runs=%d", doc.Version, len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "nuclei-security-center" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	// Two findings share a template id → one rule, two results.
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1 (deduped by template id)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	// First result: high → error, with a location from matched_at.
	if run.Results[0].Level != "error" {
		t.Errorf("result[0].level = %q, want error", run.Results[0].Level)
	}
	if len(run.Results[0].Locations) != 1 ||
		run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "https://scanme.sh/x" {
		t.Errorf("result[0] location wrong: %+v", run.Results[0].Locations)
	}
	// Second result: effective_severity critical → error; no matched_at, so the
	// location falls back to the host.
	if run.Results[1].Level != "error" {
		t.Errorf("result[1].level = %q, want error", run.Results[1].Level)
	}
	if len(run.Results[1].Locations) != 1 ||
		run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI != "other.sh" {
		t.Errorf("result[1] location should fall back to host, got %+v", run.Results[1].Locations)
	}
}
