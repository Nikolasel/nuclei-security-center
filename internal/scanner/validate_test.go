package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestValidateTemplateValid(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "Nuclei Engine Version: v3.11.0"
  exit 0
fi
if [ "$1" != "-validate" ] || [ "$2" != "-templates" ] || [ "$4" != "-no-color" ] || [ "$5" != "-disable-update-check" ]; then
  echo "unexpected arguments: $*" >&2
  exit 2
fi
grep -q "id: valid-check" "$3" || exit 2
`)
	runner := newTestRunner(t, nuclei)

	result, err := runner.ValidateTemplate(context.Background(), []byte("id: valid-check\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("valid = false, errors: %v", result.Errors)
	}
	if result.NucleiVersion != "v3.11.0" {
		t.Errorf("nuclei_version = %q, want v3.11.0", result.NucleiVersion)
	}
	if result.Errors == nil || len(result.Errors) != 0 {
		t.Errorf("errors = %#v, want an empty array", result.Errors)
	}
}

func TestValidateTemplateInvalid(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "v3.11.0"
  exit 0
fi
echo "[FTL] Could not validate template: invalid matcher" >&2
exit 1
`)
	runner := newTestRunner(t, nuclei)

	result, err := runner.ValidateTemplate(context.Background(), []byte("id: invalid\n"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("valid = true, want false")
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "invalid matcher") {
		t.Fatalf("errors = %#v", result.Errors)
	}
	if result.NucleiVersion != "v3.11.0" {
		t.Errorf("nuclei_version = %q, want v3.11.0", result.NucleiVersion)
	}
}

func TestValidateTemplateTimeoutKillsProcess(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "v3.11.0"
  exit 0
fi
sleep 5
`)
	runner := newTestRunner(t, nuclei)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_, err := runner.ValidateTemplate(ctx, []byte("id: slow\n"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
}

func TestValidateTemplateEndpointAuthAndBodyBounds(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(nil, "secret", log).Handler()

	unauthorized := httptest.NewRecorder()
	server.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/v1/templates/validate", strings.NewReader("id: x")))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Errorf("unauthorized status = %d, want 401", unauthorized.Code)
	}

	empty := httptest.NewRequest(http.MethodPost, "/v1/templates/validate", nil)
	empty.Header.Set("Authorization", "Bearer secret")
	emptyResponse := httptest.NewRecorder()
	server.ServeHTTP(emptyResponse, empty)
	if emptyResponse.Code != http.StatusBadRequest {
		t.Errorf("empty status = %d, want 400", emptyResponse.Code)
	}

	large := httptest.NewRequest(http.MethodPost, "/v1/templates/validate", bytes.NewReader(make([]byte, maxTemplateValidationUpload+1)))
	large.Header.Set("Authorization", "Bearer secret")
	largeResponse := httptest.NewRecorder()
	server.ServeHTTP(largeResponse, large)
	if largeResponse.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large status = %d, want 413", largeResponse.Code)
	}
}

func TestValidationDiagnosticsFiltersBannerAndHidesTempPath(t *testing.T) {
	const path = "/private/work/template-validation-123/template.yaml"
	output := "banner\n[VER] Started metrics server\n[ERR] load " + path + ": bad matcher\n" +
		"[ERR] directory " + filepath.Dir(path) + "\n[FTL] validation failed\n"
	got := validationDiagnostics(output, path)
	if len(got) != 3 {
		t.Fatalf("diagnostics = %#v, want three actionable lines", got)
	}
	if strings.Contains(strings.Join(got, " "), "/private/work") {
		t.Fatalf("diagnostics leak temp path: %#v", got)
	}
	if !strings.Contains(got[0], "template.yaml") {
		t.Errorf("diagnostic = %q, want normalized filename", got[0])
	}
}

func TestValidationDiagnosticsTruncatesAtUTF8Boundary(t *testing.T) {
	line := "[ERR] " + strings.Repeat("a", maxValidationLine-len("[ERR] ")-1) + "€"
	got := validationDiagnostics(line, "/tmp/template.yaml")
	if len(got) != 1 {
		t.Fatalf("diagnostics = %#v", got)
	}
	if !utf8.ValidString(got[0]) {
		t.Fatalf("diagnostic is not valid UTF-8: %q", got[0])
	}
	if len(got[0]) > maxValidationLine {
		t.Fatalf("diagnostic length = %d, want <= %d", len(got[0]), maxValidationLine)
	}
}

func newTestRunner(t *testing.T, nuclei string) *Runner {
	t.Helper()
	runner, err := NewRunner(nuclei, "/unused/naabu", "connect", t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func writeFakeNuclei(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
