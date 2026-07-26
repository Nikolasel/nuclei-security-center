package backend

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestWriteStoreErrDoesNotLeakInternalDetail(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{log: slog.New(slog.NewJSONHandler(&logs, nil))}

	// A wrapped pgx-style error, as store methods produce with %w + context.
	secret := `pq: duplicate key value violates unique constraint "targets_name_key"`
	err := fmt.Errorf("insert target: %w", fmt.Errorf("%s", secret))

	rr := httptest.NewRecorder()
	s.writeStoreErr(rr, err)

	if rr.Code != 500 {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	if body := rr.Body.String(); strings.Contains(body, "constraint") || strings.Contains(body, "pq:") {
		t.Errorf("response body leaked internal detail: %q", body)
	}
	if !strings.Contains(rr.Body.String(), "internal server error") {
		t.Errorf("body = %q, want generic message", rr.Body.String())
	}
	// The detail must still be logged server-side for debugging.
	if !strings.Contains(logs.String(), "constraint") {
		t.Errorf("internal detail was not logged: %q", logs.String())
	}
}

func TestWriteStoreErrSentinelsUnchanged(t *testing.T) {
	s := &Server{log: slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))}

	rr := httptest.NewRecorder()
	s.writeStoreErr(rr, fmt.Errorf("wrap: %w", store.ErrNotFound))
	if rr.Code != 404 {
		t.Errorf("ErrNotFound -> %d, want 404", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.writeStoreErr(rr, fmt.Errorf("wrap: %w", store.ErrConflict))
	if rr.Code != 409 {
		t.Errorf("ErrConflict -> %d, want 409", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.writeStoreErr(rr, fmt.Errorf("wrap: %w", store.ErrTemplateSetDynamic))
	if rr.Code != 409 {
		t.Errorf("ErrTemplateSetDynamic -> %d, want 409", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.writeStoreErr(rr, fmt.Errorf("wrap: %w", store.ErrTemplateSetInUse))
	if rr.Code != 409 {
		t.Errorf("ErrTemplateSetInUse -> %d, want 409", rr.Code)
	}
}
