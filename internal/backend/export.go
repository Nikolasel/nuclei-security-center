package backend

import (
	"bytes"
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
// exportable in four formats: JSON (the API row shape), CSV (a flat table for
// spreadsheets), SARIF 2.1.0 (for code-scanning / CI ingestion), and raw JSONL
// (the verbatim Nuclei output of each finding's latest occurrence — Nuclei's
// native out.jsonl shape, for tools that consume it). All honor the same filters
// as GET /api/findings, so "export what I'm looking at" works. SARIF is emitted
// as a small, stable struct via encoding/json rather than a dependency — it's a
// fixed JSON schema and stdlib is first-class here.

// exportExt maps a format to the download file extension (raw ⇒ .jsonl).
var exportExt = map[string]string{"json": "json", "csv": "csv", "sarif": "sarif", "raw": "jsonl"}

// handleExportFindings streams the filtered lifecycle findings in the requested
// format as a file download.
func (s *Server) handleExportFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "json"
	}
	ext, ok := exportExt[format]
	if !ok {
		http.Error(w, "unsupported format (want json, csv, sarif, or raw)", http.StatusBadRequest)
		return
	}

	filter := lifecycleFilterFromQuery(q)
	stamp := time.Now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="findings-%s.%s"`, stamp, ext))

	// Raw JSONL reads the verbatim occurrence payloads rather than the projected rows.
	if format == "raw" {
		raws, err := s.store.ExportLifecycleRaw(r.Context(), filter)
		if err != nil {
			s.serverError(w, "export raw findings", err)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		writeFindingsRawJSONL(w, raws)
		return
	}

	rows, err := s.store.ExportLifecycleFindings(r.Context(), filter)
	if err != nil {
		s.serverError(w, "export findings", err)
		return
	}

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

// writeFindingsRawJSONL emits one compact raw Nuclei JSON object per line — the
// native out.jsonl shape — with the lifecycle finding id prepended as a
// namespaced field so each line joins back to the projected exports. Each
// payload is already valid JSON from the store (Postgres JSONB).
func writeFindingsRawJSONL(w io.Writer, rows []store.RawExportRow) {
	var buf bytes.Buffer
	for _, r := range rows {
		buf.Reset()
		// Compact strips the JSONB pretty-printing to one line.
		if err := json.Compact(&buf, r.Raw); err != nil {
			// Not compactable (shouldn't happen) — emit verbatim, unjoined.
			_, _ = w.Write(r.Raw)
			_, _ = io.WriteString(w, "\n")
			continue
		}
		b := buf.Bytes()
		// Prepend "_nsc_lifecycle_id": <id> just inside the opening brace, keeping
		// the rest of the Nuclei payload byte-for-byte. Guard the empty object.
		if len(b) >= 2 && b[0] == '{' {
			_, _ = fmt.Fprintf(w, `{%q:%d`, rawIDField, r.ID)
			if b[1] == '}' { // "{}" → no trailing comma
				_, _ = w.Write(b[1:])
			} else {
				_, _ = io.WriteString(w, ",")
				_, _ = w.Write(b[1:])
			}
		} else {
			_, _ = w.Write(b) // non-object payload: leave as-is
		}
		_, _ = io.WriteString(w, "\n")
	}
}

// writeFindingsCSV emits a flat, spreadsheet-friendly table. The leading `id` is
// the lifecycle finding id — the shared key that joins to the JSON/SARIF/raw
// exports (and the /api/findings/{id} route).
func writeFindingsCSV(w io.Writer, rows []store.LifecycleRow) {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"id", "template_id", "name", "severity", "effective_severity", "host", "matched_at",
		"type", "detection_state", "effective_state", "disposition", "times_mitigated",
		"cve", "tags", "first_seen_at", "last_seen_at",
	})
	for _, r := range rows {
		_ = cw.Write([]string{
			strconv.FormatInt(r.ID, 10),
			r.TemplateID, r.Name, r.Severity, r.EffectiveSeverity, r.Host, r.MatchedAt,
			r.Type, r.DetectionState, r.EffectiveState, r.Disposition, strconv.Itoa(r.TimesMitigated),
			strings.Join(r.CVE, ";"), strings.Join(r.Tags, ";"),
			r.FirstSeenAt.UTC().Format(time.RFC3339), r.LastSeenAt.UTC().Format(time.RFC3339),
		})
	}
}

// rawIDField is the namespaced key carrying the lifecycle finding id in the raw
// JSONL export, so each raw line joins back to the projected exports without
// colliding with any Nuclei field.
const rawIDField = "_nsc_lifecycle_id"

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
				"nsc_lifecycle_id":   r.ID,
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
