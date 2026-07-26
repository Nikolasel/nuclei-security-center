package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestValidateTemplateBundleValidInOneProcess(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "v3.11.0"
  exit 0
fi
if [ "$1" != "-validate" ] || [ "$2" != "-templates" ] || [ "$4" != "-no-color" ] || [ "$5" != "-disable-update-check" ]; then
  echo "unexpected arguments: $*" >&2
  exit 2
fi
grep -Rq "id: batch-one" "$3" || exit 2
grep -Rq "id: batch-two" "$3" || exit 2
`)
	runner := newTestRunner(t, nuclei)
	bundle := validationTestBundle(t, map[string]string{
		"batch-one": "id: batch-one\n",
		"batch-two": "id: batch-two\n",
	})

	result, err := runner.ValidateTemplateBundle(context.Background(), bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.NucleiVersion != "v3.11.0" {
		t.Fatalf("result = %+v", result)
	}
	if result.Failures == nil || result.Errors == nil {
		t.Fatalf("result slices must be non-nil: %+v", result)
	}
}

func TestValidateTemplateBundleMapsInvalidTemplate(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "v3.11.0"
  exit 0
fi
echo "[ERR] Error occurred loading template $3/bad.yaml: invalid matcher" >&2
echo "[FTL] Could not validate templates" >&2
exit 1
`)
	runner := newTestRunner(t, nuclei)
	bundle := validationTestBundle(t, map[string]string{
		"bad":  "id: bad\n",
		"good": "id: good\n",
	})

	result, err := runner.ValidateTemplateBundle(context.Background(), bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("valid = true, want false")
	}
	if len(result.Failures) != 1 || result.Failures[0].TemplateID != "bad" {
		t.Fatalf("failures = %#v", result.Failures)
	}
	if !strings.Contains(strings.Join(result.Failures[0].Errors, " "), "invalid matcher") {
		t.Fatalf("failure diagnostics = %#v", result.Failures[0].Errors)
	}
	if strings.Contains(strings.Join(result.Failures[0].Errors, " "), runner.workRoot) {
		t.Fatalf("failure leaked work path: %#v", result.Failures[0].Errors)
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "Could not validate") {
		t.Fatalf("global errors = %#v", result.Errors)
	}
}

func TestValidateTemplateBundleTimeout(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "v3.11.0"
  exit 0
fi
sleep 5
`)
	runner := newTestRunner(t, nuclei)
	bundle := validationTestBundle(t, map[string]string{"slow": "id: slow\n"})
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_, err := runner.ValidateTemplateBundle(ctx, bytes.NewReader(bundle))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
}

func TestValidateTemplateBundleRejectsInvalidArchive(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "v3.11.0"
  exit 0
fi
exit 0
`)
	runner := newTestRunner(t, nuclei)
	_, err := runner.ValidateTemplateBundle(context.Background(), strings.NewReader("not gzip"))
	if !strings.Contains(errString(err), "invalid template bundle") {
		t.Fatalf("error = %v, want invalid bundle", err)
	}
}

func TestValidateTemplateBundleRejectsNonCustomPath(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "v3.11.0"
  exit 0
fi
exit 0
`)
	runner := newTestRunner(t, nuclei)
	bundle := makeBundle(t, []bundleFile{{name: "http/not-custom.yaml", content: "id: no\n"}}, nil, nil)
	_, err := runner.ValidateTemplateBundle(context.Background(), bytes.NewReader(bundle))
	if !strings.Contains(errString(err), "outside the custom subtree") {
		t.Fatalf("error = %v, want custom-subtree rejection", err)
	}
}

func TestValidateTemplateBatchEndpoint(t *testing.T) {
	nuclei := writeFakeNuclei(t, `if [ "$1" = "-version" ]; then
  echo "v3.11.0"
  exit 0
fi
exit 0
`)
	runner := newTestRunner(t, nuclei)
	server := NewServer(runner, "secret", slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	bundle := validationTestBundle(t, map[string]string{"endpoint": "id: endpoint\n"})

	req := httptest.NewRequest(http.MethodPost, "/v1/templates/validate-batch", bytes.NewReader(bundle))
	req.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	var result types.TemplateBatchValidationResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.NucleiVersion != "v3.11.0" {
		t.Fatalf("result = %+v", result)
	}

	badReq := httptest.NewRequest(http.MethodPost, "/v1/templates/validate-batch", strings.NewReader("not gzip"))
	badReq.Header.Set("Authorization", "Bearer secret")
	badResponse := httptest.NewRecorder()
	server.ServeHTTP(badResponse, badReq)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("bad archive status = %d, want 400 (body: %s)", badResponse.Code, badResponse.Body)
	}
}

func validationTestBundle(t *testing.T, templates map[string]string) []byte {
	t.Helper()
	files := make([]bundleFile, 0, len(templates))
	entries := make([]types.TemplateBundleEntry, 0, len(templates))
	for id, yaml := range templates {
		path := "custom/" + id + ".yaml"
		sum := sha256.Sum256([]byte(yaml))
		files = append(files, bundleFile{name: path, content: yaml})
		entries = append(entries, types.TemplateBundleEntry{
			ID: id, Path: path, SHA256: hex.EncodeToString(sum[:]),
		})
	}
	manifest := &types.TemplateBundleManifest{
		Digest: types.BundleDigest(entries), Templates: entries,
	}
	return makeBundle(t, files, manifest, nil)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
