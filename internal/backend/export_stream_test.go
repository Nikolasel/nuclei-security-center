package backend

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func lifecycleRowStream(rows []store.LifecycleRow) lifecycleRowStreamFunc {
	return func(next func(store.LifecycleRow) error) error {
		for _, row := range rows {
			if err := next(row); err != nil {
				return err
			}
		}
		return nil
	}
}

func rawRowStream(rows []store.RawExportRow) rawRowStreamFunc {
	return func(next func(store.RawExportRow) error) error {
		for _, row := range rows {
			if err := next(row); err != nil {
				return err
			}
		}
		return nil
	}
}

type byteReadWriteSeeker struct {
	data   []byte
	offset int64
}

func newByteReadWriteSeeker() *byteReadWriteSeeker {
	return &byteReadWriteSeeker{}
}

func (s *byteReadWriteSeeker) Write(p []byte) (int, error) {
	if s.offset < 0 {
		return 0, errors.New("negative write offset")
	}
	end := s.offset + int64(len(p))
	if end > int64(len(s.data)) {
		s.data = append(s.data, make([]byte, end-int64(len(s.data)))...)
	}
	copy(s.data[s.offset:end], p)
	s.offset = end
	return len(p), nil
}

func (s *byteReadWriteSeeker) Read(p []byte) (int, error) {
	if s.offset >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.offset:])
	s.offset += int64(n)
	return n, nil
}

func (s *byteReadWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = s.offset
	case io.SeekEnd:
		base = int64(len(s.data))
	default:
		return 0, errors.New("invalid seek origin")
	}
	next := base + offset
	if next < 0 {
		return 0, errors.New("negative seek offset")
	}
	s.offset = next
	return next, nil
}

type deadlineTestWriter struct {
	http.ResponseWriter
	deadlines []time.Time
}

func (w *deadlineTestWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestFindingsExportWriteDeadlineIsCleared(t *testing.T) {
	w := &deadlineTestWriter{}
	clear, err := setFindingsExportWriteDeadline(w)
	if err != nil {
		t.Fatalf("setFindingsExportWriteDeadline: %v", err)
	}
	if len(w.deadlines) != 1 || time.Until(w.deadlines[0]) <= 0 {
		t.Fatalf("initial deadline = %v, want a future deadline", w.deadlines)
	}
	clear()
	if len(w.deadlines) != 2 || !w.deadlines[1].IsZero() {
		t.Fatalf("clear deadline = %v, want zero deadline", w.deadlines)
	}
}

func TestStreamFindingsJSON(t *testing.T) {
	var buf bytes.Buffer
	truncated, err := streamFindingsJSON(&buf, 1<<20, lifecycleRowStream(sampleRows()))
	if err != nil {
		t.Fatalf("streamFindingsJSON: %v", err)
	}
	if truncated {
		t.Fatal("JSON export was unexpectedly truncated")
	}

	var got []store.LifecycleRow
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("streamed JSON is invalid: %v", err)
	}
	if len(got) != 2 || got[0].ID != 101 || got[1].ID != 102 {
		t.Fatalf("streamed rows = %#v, want lifecycle ids 101 and 102", got)
	}
}

func TestStreamFindingsJSONStopsAtByteLimit(t *testing.T) {
	var first bytes.Buffer
	if truncated, err := streamFindingsJSON(&first, 1<<20, lifecycleRowStream(sampleRows()[:1])); err != nil || truncated {
		t.Fatalf("first JSON export: truncated=%v err=%v", truncated, err)
	}

	var buf bytes.Buffer
	truncated, err := streamFindingsJSON(&buf, int64(first.Len()), lifecycleRowStream(sampleRows()))
	if err != nil {
		t.Fatalf("streamFindingsJSON: %v", err)
	}
	if !truncated || buf.Len() > first.Len() {
		t.Fatalf("JSON limit result: truncated=%v bytes=%d limit=%d", truncated, buf.Len(), first.Len())
	}
	var got []store.LifecycleRow
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("truncated JSON is invalid: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("truncated JSON rows = %d, want 1", len(got))
	}
}

func TestStreamFindingsCSV(t *testing.T) {
	var buf bytes.Buffer
	truncated, err := streamFindingsCSV(&buf, 1<<20, lifecycleRowStream(sampleRows()))
	if err != nil {
		t.Fatalf("streamFindingsCSV: %v", err)
	}
	if truncated {
		t.Fatal("CSV export was unexpectedly truncated")
	}

	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("streamed CSV is invalid: %v", err)
	}
	if len(records) != 3 || records[1][0] != "101" || records[2][0] != "102" {
		t.Fatalf("streamed CSV records = %#v", records)
	}
}

func TestStreamFindingsCSVStopsAtByteLimit(t *testing.T) {
	var first bytes.Buffer
	if truncated, err := streamFindingsCSV(&first, 1<<20, lifecycleRowStream(sampleRows()[:1])); err != nil || truncated {
		t.Fatalf("first CSV export: truncated=%v err=%v", truncated, err)
	}

	var buf bytes.Buffer
	truncated, err := streamFindingsCSV(&buf, int64(first.Len()), lifecycleRowStream(sampleRows()))
	if err != nil {
		t.Fatalf("streamFindingsCSV: %v", err)
	}
	if !truncated || buf.Len() > first.Len() {
		t.Fatalf("CSV limit result: truncated=%v bytes=%d limit=%d", truncated, buf.Len(), first.Len())
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("truncated CSV is invalid: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("truncated CSV records = %d, want header + 1 row", len(records))
	}
}

func TestStreamFindingsSARIF(t *testing.T) {
	var buf bytes.Buffer
	truncated, err := streamFindingsSARIF(&buf, 1<<20, lifecycleRowStream(sampleRows()), newByteReadWriteSeeker())
	if err != nil {
		t.Fatalf("streamFindingsSARIF: %v", err)
	}
	if truncated {
		t.Fatal("SARIF export was unexpectedly truncated")
	}

	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("streamed SARIF is invalid: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 2 || len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("streamed SARIF envelope = %#v", doc)
	}
}

func TestStreamFindingsSARIFStopsAtByteLimit(t *testing.T) {
	var first bytes.Buffer
	if truncated, err := streamFindingsSARIF(&first, 1<<20, lifecycleRowStream(sampleRows()[:1]), newByteReadWriteSeeker()); err != nil || truncated {
		t.Fatalf("first SARIF export: truncated=%v err=%v", truncated, err)
	}

	var buf bytes.Buffer
	truncated, err := streamFindingsSARIF(&buf, int64(first.Len()), lifecycleRowStream(sampleRows()), newByteReadWriteSeeker())
	if err != nil {
		t.Fatalf("streamFindingsSARIF: %v", err)
	}
	if !truncated || buf.Len() > first.Len() {
		t.Fatalf("SARIF limit result: truncated=%v bytes=%d limit=%d", truncated, buf.Len(), first.Len())
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("truncated SARIF is invalid: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("truncated SARIF results = %#v, want one result", doc.Runs[0].Results)
	}
}

func TestStreamFindingsJSONPropagatesStreamError(t *testing.T) {
	var buf bytes.Buffer
	wantErr := errors.New("database failed")
	truncated, err := streamFindingsJSON(&buf, 1<<20, func(next func(store.LifecycleRow) error) error {
		if err := next(sampleRows()[0]); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) || truncated {
		t.Fatalf("streamFindingsJSON: truncated=%v err=%v, want database error", truncated, err)
	}
}

func TestStreamFindingsJSONMarksStoreRowCap(t *testing.T) {
	var buf bytes.Buffer
	truncated, err := streamFindingsJSON(&buf, 1<<20, func(next func(store.LifecycleRow) error) error {
		if err := next(sampleRows()[0]); err != nil {
			return err
		}
		// The store maps its one-row probe result to this same limit sentinel.
		return errExportLimit
	})
	if err != nil || !truncated {
		t.Fatalf("streamFindingsJSON: truncated=%v err=%v, want row-cap truncation", truncated, err)
	}
	var got []store.LifecycleRow
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("row-capped JSON is invalid: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("row-capped JSON rows = %d, want 1", len(got))
	}
}

func TestStreamFindingsSARIFKeepsRulesOnStoreRowCap(t *testing.T) {
	var buf bytes.Buffer
	truncated, err := streamFindingsSARIF(&buf, 1<<20, func(next func(store.LifecycleRow) error) error {
		for _, row := range sampleRows() {
			if err := next(row); err != nil {
				return err
			}
		}
		return errExportLimit
	}, newByteReadWriteSeeker())
	if err != nil || !truncated {
		t.Fatalf("streamFindingsSARIF: truncated=%v err=%v, want row-cap truncation", truncated, err)
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("row-capped SARIF is invalid: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 2 || len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("row-capped SARIF envelope = %#v, want results and rule metadata", doc)
	}
}

func TestStreamFindingsSARIFBoundsRuleSpool(t *testing.T) {
	const maxBytes = int64(256 << 10)
	largeTag := strings.Repeat("x", 64<<10)
	ruleSpool := newByteReadWriteSeeker()
	var buf bytes.Buffer
	truncated, err := streamFindingsSARIF(&buf, maxBytes, func(next func(store.LifecycleRow) error) error {
		row := sampleRows()[0]
		for i := 0; i < 64; i++ {
			row.TemplateID = "template-" + strconv.Itoa(i)
			row.Tags = []string{largeTag}
			if err := next(row); err != nil {
				return err
			}
		}
		return nil
	}, ruleSpool)
	if err != nil {
		t.Fatalf("streamFindingsSARIF: truncated=%v err=%v", truncated, err)
	}
	if !truncated {
		t.Fatal("SARIF export with a bounded rule spool was not marked truncated")
	}
	if got := int64(len(ruleSpool.data)); got > maxBytes {
		t.Fatalf("rule spool size = %d, exceeds limit %d", got, maxBytes)
	}
	if got := int64(buf.Len()); got > maxBytes {
		t.Fatalf("SARIF size = %d, exceeds limit %d", got, maxBytes)
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("bounded SARIF is invalid: %v", err)
	}
}

func TestStreamFindingsRawJSONLStopsAtByteLimit(t *testing.T) {
	rows := []store.RawExportRow{
		{ID: 101, Raw: json.RawMessage(`{"template-id":"a","host":"h1"}`)},
		{ID: 102, Raw: json.RawMessage(`{"template-id":"b","host":"h2"}`)},
	}
	var first bytes.Buffer
	if truncated, err := streamFindingsRawJSONL(&first, 1<<20, rawRowStream(rows[:1])); err != nil || truncated {
		t.Fatalf("first raw export: truncated=%v err=%v", truncated, err)
	}
	maxBytes := int64(first.Len() + 1)

	var buf bytes.Buffer
	seen := 0
	truncated, err := streamFindingsRawJSONL(&buf, maxBytes, func(next func(store.RawExportRow) error) error {
		for _, row := range rows {
			seen++
			if err := next(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("streamFindingsRawJSONL: %v", err)
	}
	if !truncated {
		t.Fatal("raw export was not marked truncated")
	}
	if seen != 2 {
		t.Fatalf("stream consumed %d rows, want the second row to trip the limit", seen)
	}
	if buf.Len() > int(maxBytes) {
		t.Fatalf("raw export size = %d, exceeds limit %d", buf.Len(), maxBytes)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("raw export emitted %d lines, want one complete line", len(lines))
	}
	var decoded map[string]any
	if err := json.Unmarshal(lines[0], &decoded); err != nil {
		t.Fatalf("truncated raw line is invalid JSON: %v", err)
	}
	if decoded[rawIDField] != float64(101) {
		t.Fatalf("raw lifecycle id = %v, want 101", decoded[rawIDField])
	}
}

func TestFindingsExportAdmission(t *testing.T) {
	s := &Server{exportSlots: make(chan struct{}, 1)}
	release, ok := s.tryAcquireFindingsExport()
	if !ok {
		t.Fatal("first export was rejected")
	}

	if secondRelease, ok := s.tryAcquireFindingsExport(); ok {
		secondRelease()
		t.Fatal("concurrent export was admitted past the limit")
	}

	release()
	if nextRelease, ok := s.tryAcquireFindingsExport(); !ok {
		t.Fatal("export was not admitted after the slot was released")
	} else {
		nextRelease()
	}
}
