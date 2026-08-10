package scanner

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestRunnerStartRejectsWhenAtCapacity(t *testing.T) {
	runner, err := NewRunner("/bin/false", "/bin/false", "connect", t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.admission.acquire(0); err != nil {
		t.Fatalf("fill admission: %v", err)
	}
	defer runner.admission.release()

	_, err = runner.Start(types.ScanSpec{Targets: []string{"scanme.sh"}})
	if !errors.Is(err, ErrScanCapacity) {
		t.Fatalf("Start error = %v, want ErrScanCapacity", err)
	}
}

func TestScannerStartReturnsTooManyRequestsWhenAtCapacity(t *testing.T) {
	runner, err := NewRunner("/bin/false", "/bin/false", "connect", t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.admission.acquire(0); err != nil {
		t.Fatalf("fill admission: %v", err)
	}
	defer runner.admission.release()

	server := NewServer(runner, "secret", slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(`{"targets":["scanme.sh"]}`))
	req.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body=%q", response.Code, http.StatusTooManyRequests, response.Body.String())
	}
}

func TestAdmissionInvalidInitialLimitFallsBackSafely(t *testing.T) {
	admission := newScanAdmission(MaxConcurrentScansCeiling + 1)
	if admission.fallback != DefaultMaxConcurrentScans || admission.limit != DefaultMaxConcurrentScans {
		t.Fatalf("invalid initial limit produced fallback/limit %d/%d, want %d/%d", admission.fallback, admission.limit, DefaultMaxConcurrentScans, DefaultMaxConcurrentScans)
	}
}

func TestAdmissionOmittedLimitRestoresLocalFallback(t *testing.T) {
	admission := newScanAdmission(2)
	if err := admission.acquire(5); err != nil {
		t.Fatalf("override acquire: %v", err)
	}
	admission.release()

	if err := admission.acquire(0); err != nil {
		t.Fatalf("first fallback acquire: %v", err)
	}
	if err := admission.acquire(0); err != nil {
		t.Fatalf("second fallback acquire: %v", err)
	}
	if err := admission.acquire(0); !errors.Is(err, ErrScanCapacity) {
		t.Fatalf("third fallback acquire = %v, want ErrScanCapacity", err)
	}
	admission.release()
	admission.release()
}
