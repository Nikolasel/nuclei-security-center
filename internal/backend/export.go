package backend

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Findings export (Phase 2, slice 3). The deduplicated lifecycle list is
// exportable in four formats: JSON (the API row shape), CSV (a flat table for
// spreadsheets), SARIF 2.1.0 (for code-scanning / CI ingestion), and raw JSONL
// (the preserved Nuclei output of each finding's latest occurrence — Nuclei's
// native out.jsonl shape, for tools that consume it). All honor the same filters
// as GET /api/findings, so "export what I'm looking at" works. SARIF is emitted
// as a small, stable struct via encoding/json rather than a dependency — it's a
// fixed JSON schema and stdlib is first-class here.

// exportExt maps a format to the download file extension (raw ⇒ .jsonl).
var exportExt = map[string]string{"json": "json", "csv": "csv", "sarif": "sarif", "raw": "jsonl"}

const (
	exportMaxBytes                 = 64 << 20
	maxConcurrentFindingExports    = 4
	exportWriteTimeout             = 10 * time.Minute
	exportRetryAfter               = 30 * time.Second
	exportTruncatedHeader          = "X-NSC-Export-Truncated"
	exportRowCountHeader           = "X-NSC-Export-Row-Count"
	exportMaxBytesHeader           = "X-NSC-Export-Max-Bytes"
	exportMissingOccurrencesHeader = "X-NSC-Export-Missing-Occurrences"
	sarifResultsPrefix             = `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"results":[`
	sarifToolPrefix                = `],"tool":{"driver":{"name":"nuclei-security-center","informationUri":"https://github.com/Nikolasel/nuclei-security-center","rules":[`
	sarifSuffix                    = `]}}}]}`
)

var errExportLimit = errors.New("finding export limit reached")

type lifecycleRowStreamFunc func(func(store.LifecycleRow) error) error
type rawRowStreamFunc func(func(store.RawExportRow) error) error

type findingsExportStore interface {
	StreamLifecycleFindings(context.Context, store.FindingQuery, func(store.LifecycleRow) error) (bool, error)
	StreamLifecycleRaw(context.Context, store.FindingQuery, func(store.RawExportRow) error) (bool, int64, error)
}

func (s *Server) findingsExportSlots() chan struct{} {
	s.exportSlotsOnce.Do(func() {
		if s.exportSlots == nil {
			s.exportSlots = make(chan struct{}, maxConcurrentFindingExports)
		}
	})
	return s.exportSlots
}

// ValidateFindingsExportSpoolDir verifies the backend-local scratch directory
// before the process starts serving requests. The check intentionally creates
// and removes a file: statting the directory alone does not prove that the
// runtime user can write there.
func ValidateFindingsExportSpoolDir(dir string) error {
	if dir == "" {
		return errors.New("export spool directory is empty")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat export spool directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("export spool path %q is not a directory", dir)
	}
	tmp, err := os.CreateTemp(dir, ".nsc-export-startup-check-*")
	if err != nil {
		return fmt.Errorf("create export spool probe: %w", err)
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close export spool probe: %w", err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove export spool probe: %w", err)
	}
	return nil
}

func setFindingsExportWriteDeadline(w http.ResponseWriter) (func(), error) {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(exportWriteTimeout)); err != nil {
		return nil, fmt.Errorf("response writer does not support export write deadlines: %w", err)
	}
	return func() { _ = controller.SetWriteDeadline(time.Time{}) }, nil
}

type exportWriter struct {
	w         io.Writer
	remaining int64
}

func newExportWriter(w io.Writer, maxBytes int64) *exportWriter {
	return &exportWriter{w: w, remaining: maxBytes}
}

func (w *exportWriter) canWrite(size int64) bool {
	return size >= 0 && size <= w.remaining
}

func (w *exportWriter) write(p []byte) error {
	if !w.canWrite(int64(len(p))) {
		return errExportLimit
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}

func (s *Server) tryAcquireFindingsExport() (func(), bool) {
	slots := s.findingsExportSlots()
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		return nil, false
	}
}

// handleExportFindings streams the filtered lifecycle findings in the requested
// format as a file download. The process-level admission limit prevents many
// viewers from holding independent database cursors and encoders at once. The
// bounded temporary files separate database speed from client download speed:
// database errors are returned before any download headers/body are sent.
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

	filter, err := findingQueryFromRequest(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := store.ValidateFindingQuery(filter); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	exportStore := s.exportStore
	if exportStore == nil {
		if s.store == nil {
			s.serverError(w, "export findings", errors.New("findings export store is unavailable"))
			return
		}
		exportStore = s.store
	}
	release, ok := s.tryAcquireFindingsExport()
	if !ok {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(exportRetryAfter/time.Second), 10))
		http.Error(w, "too many findings exports in progress", http.StatusTooManyRequests)
		return
	}
	defer release()

	tmp, err := os.CreateTemp(s.exportSpoolDir, "nsc-findings-export-*")
	if err != nil {
		s.serverError(w, "prepare findings export", err)
		return
	}
	tmpName := tmp.Name()
	// Unlink the open file immediately where the platform permits it. This keeps
	// a SIGKILL from leaving a full export behind; the named-file fallback is
	// retained for platforms that cannot remove an open file.
	cleanupName := tmpName
	if err := os.Remove(tmpName); err == nil {
		cleanupName = ""
	}
	defer func() {
		_ = tmp.Close()
		if cleanupName != "" {
			_ = os.Remove(cleanupName)
		}
	}()

	var sarifRuleSpool *os.File
	var sarifRuleCleanupName string
	if format == "sarif" {
		sarifRuleSpool, err = os.CreateTemp(s.exportSpoolDir, "nsc-findings-sarif-rules-*")
		if err != nil {
			s.serverError(w, "prepare findings export", err)
			return
		}
		sarifRuleCleanupName = sarifRuleSpool.Name()
		if err := os.Remove(sarifRuleCleanupName); err == nil {
			sarifRuleCleanupName = ""
		}
		defer func() {
			_ = sarifRuleSpool.Close()
			if sarifRuleCleanupName != "" {
				_ = os.Remove(sarifRuleCleanupName)
			}
		}()
	}

	var exportedRows int64
	var missingRawOccurrences int64
	lifecycleStream := func(next func(store.LifecycleRow) error) error {
		rowCapped, err := exportStore.StreamLifecycleFindings(r.Context(), filter, func(row store.LifecycleRow) error {
			if err := next(row); err != nil {
				return err
			}
			exportedRows++
			return nil
		})
		if err != nil {
			return err
		}
		if rowCapped {
			return errExportLimit
		}
		return nil
	}
	rawStream := func(next func(store.RawExportRow) error) error {
		rowCapped, missing, err := exportStore.StreamLifecycleRaw(r.Context(), filter, func(row store.RawExportRow) error {
			if err := next(row); err != nil {
				return err
			}
			exportedRows++
			return nil
		})
		missingRawOccurrences = missing
		if err != nil {
			return err
		}
		if rowCapped {
			return errExportLimit
		}
		return nil
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	var truncated bool
	var streamErr error

	// Raw JSONL reads the verbatim occurrence payloads rather than the projected rows.
	if format == "raw" {
		truncated, streamErr = streamFindingsRawJSONL(tmp, exportMaxBytes, rawStream)
	} else {
		switch format {
		case "json":
			truncated, streamErr = streamFindingsJSON(tmp, exportMaxBytes, lifecycleStream)
		case "csv":
			truncated, streamErr = streamFindingsCSV(tmp, exportMaxBytes, lifecycleStream)
		case "sarif":
			truncated, streamErr = streamFindingsSARIF(tmp, exportMaxBytes, lifecycleStream, sarifRuleSpool)
		}
	}
	if streamErr != nil {
		s.serverError(w, "export findings", streamErr)
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		s.serverError(w, "rewind findings export", err)
		return
	}
	stat, err := tmp.Stat()
	if err != nil {
		s.serverError(w, "stat findings export", err)
		return
	}
	clearWriteDeadline, err := setFindingsExportWriteDeadline(w)
	if err != nil {
		s.serverError(w, "prepare findings export response", err)
		return
	}
	defer clearWriteDeadline()

	contentType := map[string]string{
		"json":  "application/json",
		"csv":   "text/csv",
		"sarif": "application/sarif+json",
		"raw":   "application/x-ndjson",
	}[format]
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="findings-%s.%s"`, stamp, ext))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set(exportMaxBytesHeader, strconv.FormatInt(exportMaxBytes, 10))
	w.Header().Set(exportTruncatedHeader, strconv.FormatBool(truncated))
	w.Header().Set(exportRowCountHeader, strconv.FormatInt(exportedRows, 10))
	w.Header().Set("Cache-Control", "no-store")
	if format == "raw" {
		w.Header().Set(exportMissingOccurrencesHeader, strconv.FormatInt(missingRawOccurrences, 10))
	}
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.WriteHeader(http.StatusOK)
	if written, copyErr := io.Copy(w, tmp); copyErr != nil || written != stat.Size() {
		if s.log != nil {
			if r.Context().Err() != nil {
				s.log.Debug("client canceled findings export", "err", copyErr, "written", written, "want", stat.Size())
			} else {
				s.log.Error("write findings export", "err", copyErr, "written", written, "want", stat.Size())
			}
		}
		// The response has started, so a normal return would make a partial
		// download look successful. ErrAbortHandler tells net/http to close
		// the connection without writing a terminating chunk.
		panic(http.ErrAbortHandler)
	}
}

func streamFindingsJSON(w io.Writer, maxBytes int64, stream lifecycleRowStreamFunc) (bool, error) {
	ew := newExportWriter(w, maxBytes)
	started := false
	first := true
	streamErr := stream(func(row store.LifecycleRow) error {
		if !started {
			if err := ew.write([]byte("[\n")); err != nil {
				return err
			}
			started = true
		}
		encoded, err := prettyJSONRow(row)
		if err != nil {
			return err
		}
		chunk := make([]byte, 0, len(encoded)+2)
		if !first {
			chunk = append(chunk, ',', '\n')
		}
		chunk = append(chunk, encoded...)
		if !ew.canWrite(int64(len(chunk)) + 3) { // newline + closing bracket + newline
			return errExportLimit
		}
		if err := ew.write(chunk); err != nil {
			return err
		}
		first = false
		return nil
	})
	truncated := errors.Is(streamErr, errExportLimit)
	if streamErr != nil && !truncated {
		return false, streamErr
	}
	if !started {
		if err := ew.write([]byte("[]\n")); err != nil {
			return truncated, err
		}
		return truncated, nil
	}
	if err := ew.write([]byte("\n]\n")); err != nil {
		return truncated, err
	}
	return truncated, nil
}

func prettyJSONRow(row store.LifecycleRow) ([]byte, error) {
	encoded, err := json.MarshalIndent(row, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append([]byte("  "), encoded...)
	return bytes.ReplaceAll(encoded, []byte("\n"), []byte("\n  ")), nil
}

func streamFindingsCSV(w io.Writer, maxBytes int64, stream lifecycleRowStreamFunc) (bool, error) {
	ew := newExportWriter(w, maxBytes)
	header, err := csvRecordBytes(findingsCSVHeader())
	if err != nil {
		return false, err
	}
	headerWritten := false
	streamErr := stream(func(row store.LifecycleRow) error {
		if !headerWritten {
			if err := ew.write(header); err != nil {
				return err
			}
			headerWritten = true
		}
		line, err := csvRecordBytes(lifecycleCSVCells(row))
		if err != nil {
			return err
		}
		return ew.write(line)
	})
	truncated := errors.Is(streamErr, errExportLimit)
	if streamErr != nil && !truncated {
		return false, streamErr
	}
	if !headerWritten {
		if err := ew.write(header); err != nil {
			return truncated, err
		}
	}
	return truncated, nil
}

func streamFindingsRawJSONL(w io.Writer, maxBytes int64, stream rawRowStreamFunc) (bool, error) {
	ew := newExportWriter(w, maxBytes)
	streamErr := stream(func(row store.RawExportRow) error {
		return ew.write(rawExportLine(row))
	})
	truncated := errors.Is(streamErr, errExportLimit)
	if streamErr != nil && !truncated {
		return false, streamErr
	}
	return truncated, nil
}

func streamFindingsSARIF(w io.Writer, maxBytes int64, stream lifecycleRowStreamFunc, ruleSpool io.ReadWriteSeeker) (bool, error) {
	ew := newExportWriter(w, maxBytes)
	ruleWriter := newExportWriter(ruleSpool, maxBytes)
	rulesByID := map[string]struct{}{}
	truncatedRules := false
	started := false
	firstResult := true

	streamErr := stream(func(row store.LifecycleRow) error {
		if !started {
			if err := ew.write([]byte(sarifResultsPrefix)); err != nil {
				return err
			}
			started = true
		}
		result, err := json.Marshal(sarifResultForRow(row))
		if err != nil {
			return err
		}
		chunk := make([]byte, 0, len(result)+1)
		if !firstResult {
			chunk = append(chunk, ',')
		}
		chunk = append(chunk, result...)
		minimalSuffix := int64(len(sarifToolPrefix) + len(sarifSuffix))
		if !ew.canWrite(int64(len(chunk)) + minimalSuffix) {
			return errExportLimit
		}
		if err := ew.write(chunk); err != nil {
			return err
		}
		firstResult = false

		// Once the bounded rule spool is full, no new rule can be retained or
		// emitted, so stop growing the de-duplication map as well.
		if truncatedRules {
			return nil
		}
		if _, seen := rulesByID[row.TemplateID]; seen {
			return nil
		}
		rulesByID[row.TemplateID] = struct{}{}
		encoded, err := json.Marshal(sarifRuleForRow(row))
		if err != nil {
			return err
		}
		encoded = append(encoded, '\n')
		if err := ruleWriter.write(encoded); err != nil {
			if errors.Is(err, errExportLimit) {
				truncatedRules = true
				return nil
			}
			return err
		}
		return nil
	})
	truncated := errors.Is(streamErr, errExportLimit)
	if streamErr != nil && !truncated {
		return false, streamErr
	}
	if truncatedRules {
		// Rule metadata is part of the SARIF export. Even when every result
		// fits, omitting a rule makes the document incomplete.
		truncated = true
	}
	if _, err := ruleSpool.Seek(0, io.SeekStart); err != nil {
		return truncated, fmt.Errorf("rewind SARIF rule spool: %w", err)
	}

	if !started {
		if err := ew.write([]byte(sarifResultsPrefix)); err != nil {
			return truncated, err
		}
		started = true
	}
	if err := ew.write([]byte(sarifToolPrefix)); err != nil {
		return truncated, err
	}
	reader := bufio.NewReader(ruleSpool)
	firstRule := true
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = line[:len(line)-1]
			chunk := make([]byte, 0, len(line)+1)
			if !firstRule {
				chunk = append(chunk, ',')
			}
			chunk = append(chunk, line...)
			if !ew.canWrite(int64(len(chunk) + len(sarifSuffix))) {
				// Rule metadata is part of the SARIF export. Even when every
				// result fits, omitting a rule makes the document incomplete.
				truncated = true
				break
			}
			if err := ew.write(chunk); err != nil {
				return truncated, err
			}
			firstRule = false
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return truncated, err
		}
	}
	if err := ew.write([]byte(sarifSuffix)); err != nil {
		return truncated, err
	}
	return truncated, nil
}

func csvRecordBytes(cells []string) ([]byte, error) {
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	writeCSVRecord(cw, cells)
	cw.Flush()
	if err := cw.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func findingsCSVHeader() []string {
	return []string{
		"id", "template_id", "name", "severity", "effective_severity", "host", "matched_at",
		"type", "detection_state", "effective_state", "disposition", "times_mitigated",
		"cve", "tags", "first_seen_at", "last_seen_at", "target_ids",
	}
}

func lifecycleCSVCells(r store.LifecycleRow) []string {
	return []string{
		strconv.FormatInt(r.ID, 10),
		r.TemplateID, r.Name, r.Severity, r.EffectiveSeverity, r.Host, r.MatchedAt,
		r.Type, r.DetectionState, r.EffectiveState, r.Disposition, strconv.Itoa(r.TimesMitigated),
		strings.Join(r.CVE, ";"), strings.Join(r.Tags, ";"),
		r.FirstSeenAt.UTC().Format(time.RFC3339), r.LastSeenAt.UTC().Format(time.RFC3339),
		strings.Join(r.TargetIDs, ";"),
	}
}

func rawExportLine(r store.RawExportRow) []byte {
	var compact bytes.Buffer
	if err := json.Compact(&compact, r.Raw); err != nil {
		return append(append([]byte(nil), r.Raw...), '\n')
	}
	b := compact.Bytes()
	var line bytes.Buffer
	if len(b) >= 2 && b[0] == '{' {
		line.WriteString(`{"_nsc_lifecycle_id":`)
		line.WriteString(strconv.FormatInt(r.ID, 10))
		if b[1] == '}' {
			line.Write(b[1:])
		} else {
			line.WriteByte(',')
			line.Write(b[1:])
		}
	} else {
		line.Write(b)
	}
	line.WriteByte('\n')
	return line.Bytes()
}

func sarifRuleForRow(r store.LifecycleRow) sarifRule {
	return sarifRule{
		ID:               r.TemplateID,
		Name:             r.Name,
		ShortDescription: sarifText{Text: firstNonEmpty(r.Name, r.TemplateID)},
		Properties:       sarifRuleProps{Tags: r.Tags},
	}
}

func sarifResultForRow(r store.LifecycleRow) sarifResult {
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
			"target_ids":         r.TargetIDs,
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
	return res
}

// writeCSVRecord neutralizes every cell before writing it, so untrusted
// finding content (host/matched_at are influenced by the scanned host) can't
// smuggle a spreadsheet formula into the export.
func writeCSVRecord(cw *csv.Writer, cells []string) {
	for i, c := range cells {
		cells[i] = neutralizeCSVCell(c)
	}
	_ = cw.Write(cells)
}

// neutralizeCSVCell defuses CSV formula injection (CWE-1236). A spreadsheet
// (Excel/Sheets/LibreOffice) evaluates a cell whose first character is one of
// = + - @ (or a leading tab/CR), so e.g. a host of `=HYPERLINK(...)` or a
// legacy DDE payload would execute on the analyst's workstation. Prefixing a
// single quote forces the value to be treated as literal text. encoding/csv
// only handles delimiter/quote/newline correctness — not this.
func neutralizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// rawIDField is the namespaced key carrying the lifecycle finding id in the raw
// JSONL export, so each raw line joins back to the projected exports without
// colliding with any Nuclei field.
const rawIDField = "_nsc_lifecycle_id"

// --- SARIF 2.1.0 (minimal, valid subset for code-scanning ingestion) ---
// These envelope types are also used by tests to validate the hand-built JSON
// emitted by streamFindingsSARIF; production only needs the encoder structs.

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
