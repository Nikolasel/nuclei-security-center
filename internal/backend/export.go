package backend

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Findings export (Phase 2, slice 3). The deduplicated lifecycle list is
// exportable in three formats: JSON (the API row shape), CSV (a flat table for
// spreadsheets), and SARIF 2.1.0 (for code-scanning / CI ingestion). All three
// honor the same filters as GET /api/findings, so "export what I'm looking at"
// works. SARIF is emitted as a small, stable struct via encoding/json rather
// than a dependency — it's a fixed JSON schema and stdlib is first-class here.

// handleExportFindings streams the filtered lifecycle findings in the requested
// format as a file download.
func (s *Server) handleExportFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" && format != "sarif" {
		http.Error(w, "unsupported format (want json, csv, or sarif)", http.StatusBadRequest)
		return
	}

	rows, err := s.store.ExportLifecycleFindings(r.Context(), lifecycleFilterFromQuery(q))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ext := format
	stamp := time.Now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="findings-%s.%s"`, stamp, ext))

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if rows == nil {
			rows = []store.LifecycleRow{}
		}
		_ = enc.Encode(rows)
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		writeFindingsCSV(w, rows)
	case "sarif":
		w.Header().Set("Content-Type", "application/sarif+json")
		writeFindingsSARIF(w, rows)
	}
}

// writeFindingsCSV emits a flat, spreadsheet-friendly table.
func writeFindingsCSV(w io.Writer, rows []store.LifecycleRow) {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"template_id", "name", "severity", "effective_severity", "host", "matched_at",
		"type", "detection_state", "effective_state", "disposition", "times_mitigated",
		"cve", "tags", "first_seen_at", "last_seen_at",
	})
	for _, r := range rows {
		_ = cw.Write([]string{
			r.TemplateID, r.Name, r.Severity, r.EffectiveSeverity, r.Host, r.MatchedAt,
			r.Type, r.DetectionState, r.EffectiveState, r.Disposition, strconv.Itoa(r.TimesMitigated),
			strings.Join(r.CVE, ";"), strings.Join(r.Tags, ";"),
			r.FirstSeenAt.UTC().Format(time.RFC3339), r.LastSeenAt.UTC().Format(time.RFC3339),
		})
	}
}

// --- SARIF 2.1.0 (minimal, valid subset for code-scanning ingestion) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       sarifRuleProps `json:"properties,omitempty"`
}

type sarifRuleProps struct {
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifLevel maps a Nuclei severity to a SARIF result level.
func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default: // low, info, unknown
		return "note"
	}
}

func writeFindingsSARIF(w io.Writer, rows []store.LifecycleRow) {
	rulesByID := map[string]sarifRule{}
	var rules []sarifRule
	results := make([]sarifResult, 0, len(rows))

	for _, r := range rows {
		if _, ok := rulesByID[r.TemplateID]; !ok {
			rule := sarifRule{
				ID:               r.TemplateID,
				Name:             r.Name,
				ShortDescription: sarifText{Text: firstNonEmpty(r.Name, r.TemplateID)},
				Properties:       sarifRuleProps{Tags: r.Tags},
			}
			rulesByID[r.TemplateID] = rule
			rules = append(rules, rule)
		}

		loc := firstNonEmpty(r.MatchedAt, r.Host)
		res := sarifResult{
			RuleID:  r.TemplateID,
			Level:   sarifLevel(r.EffectiveSeverity),
			Message: sarifText{Text: firstNonEmpty(r.Name, r.TemplateID)},
			Properties: map[string]any{
				"severity":           r.Severity,
				"effective_severity": r.EffectiveSeverity,
				"detection_state":    r.DetectionState,
				"effective_state":    r.EffectiveState,
				"disposition":        r.Disposition,
				"times_mitigated":    r.TimesMitigated,
				"host":               r.Host,
				"first_seen_at":      r.FirstSeenAt.UTC().Format(time.RFC3339),
				"last_seen_at":       r.LastSeenAt.UTC().Format(time.RFC3339),
			},
		}
		if len(r.CVE) > 0 {
			res.Properties["cve"] = r.CVE
		}
		if loc != "" {
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: loc}},
			}}
		}
		results = append(results, res)
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "nuclei-security-center",
				InformationURI: "https://github.com/Nikolasel/nuclei-security-center",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
}
