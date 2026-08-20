package backend

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestValidateFindingsExportSpoolDir(t *testing.T) {
	dir := t.TempDir()
	if err := ValidateFindingsExportSpoolDir(dir); err != nil {
		t.Fatalf("valid export spool directory: %v", err)
	}

	file := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFindingsExportSpoolDir(file); err == nil {
		t.Fatal("file path unexpectedly accepted as an export spool directory")
	}
	if err := ValidateFindingsExportSpoolDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing path unexpectedly accepted as an export spool directory")
	}
}

type exportResponseRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *exportResponseRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

type fakeFindingsExportStore struct {
	rows            []store.LifecycleRow
	rawRows         []store.RawExportRow
	rowCapped       bool
	missingRawCount int64
}

func (s fakeFindingsExportStore) StreamLifecycleFindings(_ context.Context, _ store.FindingQuery, next func(store.LifecycleRow) error) (bool, error) {
	for _, row := range s.rows {
		if err := next(row); err != nil {
			return false, err
		}
	}
	return s.rowCapped, nil
}

func (s fakeFindingsExportStore) StreamLifecycleRaw(_ context.Context, _ store.FindingQuery, next func(store.RawExportRow) error) (bool, int64, error) {
	for _, row := range s.rawRows {
		if err := next(row); err != nil {
			return false, s.missingRawCount, err
		}
	}
	return false, s.missingRawCount, nil
}

func TestHandleExportFindingsResponseContract(t *testing.T) {
	dir := t.TempDir()
	writer := &exportResponseRecorder{ResponseRecorder: httptest.NewRecorder()}
	server := &Server{
		exportSlots:    make(chan struct{}, maxConcurrentFindingExports),
		exportSpoolDir: dir,
		exportStore: fakeFindingsExportStore{
			rows:      sampleRows()[:1],
			rowCapped: true,
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/findings/export?format=json", nil)
	server.handleExportFindings(writer, request)

	if writer.Code != http.StatusOK {
		t.Fatalf("export status = %d, want 200", writer.Code)
	}
	if writer.Header().Get(exportTruncatedHeader) != "true" {
		t.Fatalf("export truncation header = %q, want true", writer.Header().Get(exportTruncatedHeader))
	}
	if got, want := writer.Header().Get(exportRowCountHeader), "1"; got != want {
		t.Fatalf("export row count header = %q, want %q", got, want)
	}
	if got, want := writer.Header().Get("Content-Length"), strconv.Itoa(writer.Body.Len()); got != want {
		t.Fatalf("Content-Length = %q, want %q", got, want)
	}
	if !strings.HasPrefix(writer.Header().Get("Content-Disposition"), `attachment; filename="findings-`) {
		t.Fatalf("Content-Disposition = %q, want an attachment filename", writer.Header().Get("Content-Disposition"))
	}
	if got := writer.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var rows []store.LifecycleRow
	if err := json.Unmarshal(writer.Body.Bytes(), &rows); err != nil {
		t.Fatalf("export body is invalid JSON: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("export rows = %d, want 1", len(rows))
	}
	if len(writer.deadlines) != 2 || writer.deadlines[0].IsZero() || !writer.deadlines[1].IsZero() {
		t.Fatalf("write deadlines = %#v, want set then clear", writer.deadlines)
	}

	rawWriter := &exportResponseRecorder{ResponseRecorder: httptest.NewRecorder()}
	rawRequest := httptest.NewRequest(http.MethodGet, "/api/findings/export?format=raw", nil)
	server.exportStore = fakeFindingsExportStore{
		rawRows:         []store.RawExportRow{{ID: 103, Raw: json.RawMessage(`{"template-id":"example"}`)}},
		missingRawCount: 1,
	}
	server.handleExportFindings(rawWriter, rawRequest)
	if rawWriter.Code != http.StatusOK {
		t.Fatalf("raw export status = %d, want 200", rawWriter.Code)
	}
	if got, want := rawWriter.Header().Get(exportMissingOccurrencesHeader), "1"; got != want {
		t.Fatalf("raw missing-occurrences header = %q, want %q", got, want)
	}
	if got, want := rawWriter.Header().Get(exportRowCountHeader), "1"; got != want {
		t.Fatalf("raw row count header = %q, want %q", got, want)
	}
	if rawWriter.Body.Len() == 0 {
		t.Fatal("raw export body is empty despite one available raw row")
	}
}

func TestHandleExportFindingsRejectsMissingStore(t *testing.T) {
	server := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	writer := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/findings/export?format=json", nil)
	server.handleExportFindings(writer, request)
	if writer.Code != http.StatusInternalServerError {
		t.Fatalf("missing-store status = %d, want 500", writer.Code)
	}
}

func TestHandleExportFindingsAdmissionRetryAfterHint(t *testing.T) {
	slots := make(chan struct{}, maxConcurrentFindingExports)
	for i := 0; i < maxConcurrentFindingExports; i++ {
		slots <- struct{}{}
	}
	server := &Server{exportSlots: slots, exportStore: fakeFindingsExportStore{}}
	writer := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/findings/export?format=json", nil)
	server.handleExportFindings(writer, request)

	if writer.Code != http.StatusTooManyRequests {
		t.Fatalf("export status = %d, want 429", writer.Code)
	}
	if got, want := writer.Header().Get("Retry-After"), "30"; got != want {
		t.Fatalf("Retry-After = %q, want %q", got, want)
	}
}
