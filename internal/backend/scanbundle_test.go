package backend

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func sampleBundleForTest() types.ScanBundle {
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return types.ScanBundle{
		Format:        types.ScanBundleFormat,
		FormatVersion: types.ScanBundleFormatVersion,
		ExportedAt:    t0,
		Scan: types.ScanBundleScan{
			ID:        types.NewID(),
			State:     string(types.ScanComplete),
			Source:    "adhoc",
			CreatedAt: t0,
			Spec:      json.RawMessage(`{}`),
		},
		Findings: []types.ScanBundleFinding{{
			ID: 1, TemplateID: "cve-x", Name: "X", Severity: "high",
			Host: "scanme.invalid", MatchedAt: "https://scanme.invalid/", Type: "http",
			CreatedAt: t0, Raw: json.RawMessage(`{"template-id":"cve-x"}`),
		}},
	}
}

func readZipBundleManifest(body []byte) ([]byte, error) {
	rc, err := openScanBundleManifest(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	manifest, err := io.ReadAll(io.LimitReader(rc, types.ScanBundleMaxManifest+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", types.ScanBundleManifestName, err)
	}
	if len(manifest) > types.ScanBundleMaxManifest {
		return nil, fmt.Errorf("bundle %s exceeds the %d MiB limit", types.ScanBundleManifestName, types.ScanBundleMaxManifest>>20)
	}
	return manifest, nil
}

func TestIsZipBundle(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want bool
	}{
		{"zip local header", []byte{'P', 'K', 3, 4, 0, 0}, true},
		{"zip empty archive", []byte{'P', 'K', 5, 6}, true},
		{"zip spanned", []byte{'P', 'K', 7, 8}, true},
		{"json document", []byte(`{"format":"nuclei-security-center/scan-bundle"}`), false},
		{"too short", []byte{'P', 'K'}, false},
		{"garbage", []byte("PKXX"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isZipBundle(tc.body); got != tc.want {
				t.Errorf("isZipBundle(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestReadZipBundleManifest(t *testing.T) {
	manifest := []byte(`{"format":"nuclei-security-center/scan-bundle","format_version":1}`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create(types.ScanBundleManifestName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	// A second, unrelated entry must be ignored.
	extra, _ := zw.Create("raw.jsonl")
	_, _ = extra.Write([]byte("{}"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := readZipBundleManifest(buf.Bytes())
	if err != nil {
		t.Fatalf("readZipBundleManifest: %v", err)
	}
	if !bytes.Equal(got, manifest) {
		t.Errorf("manifest = %q, want %q", got, manifest)
	}
}

func TestReadZipBundleManifestRejects(t *testing.T) {
	t.Run("not a zip", func(t *testing.T) {
		if _, err := readZipBundleManifest([]byte(`{"format":"x"}`)); err == nil {
			t.Fatal("expected error for non-zip body")
		}
	})
	t.Run("missing manifest entry", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create("other.txt")
		_, _ = f.Write([]byte("nope"))
		_ = zw.Close()
		if _, err := readZipBundleManifest(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "no manifest.json") {
			t.Fatalf("expected missing-manifest error, got %v", err)
		}
	})
	t.Run("oversized manifest entry", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create(types.ScanBundleManifestName)
		_, _ = f.Write(bytes.Repeat([]byte("x"), types.ScanBundleMaxManifest+1))
		_ = zw.Close()
		if _, err := readZipBundleManifest(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("expected size-limit error, got %v", err)
		}
	})
	t.Run("multiple manifest entries", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for range 2 {
			f, _ := zw.Create(types.ScanBundleManifestName)
			_, _ = f.Write([]byte(`{"format":"nuclei-security-center/scan-bundle"}`))
		}
		_ = zw.Close()
		if _, err := readZipBundleManifest(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "more than one manifest.json") {
			t.Fatalf("expected multiple-manifest error, got %v", err)
		}
	})
	t.Run("excessive entry count", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		manifest, err := zw.Create(types.ScanBundleManifestName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manifest.Write([]byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < types.ScanBundleMaxEntries; i++ {
			entry, err := zw.Create(fmt.Sprintf("extra/%d", i))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write(nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := readZipBundleManifest(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "zip entries") {
			t.Fatalf("expected zip entry-count error, got %v", err)
		}
	})
	t.Run("declared entry count is checked", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, name := range []string{types.ScanBundleManifestName, "extra.txt"} {
			f, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte(`{}`)); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		end := bytes.LastIndex(buf.Bytes(), []byte("PK\x05\x06"))
		if end < 0 {
			t.Fatal("zip end record not found")
		}
		binary.LittleEndian.PutUint16(buf.Bytes()[end+10:end+12], 1)
		if _, err := readZipBundleManifest(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "declares") {
			t.Fatalf("expected declared-count error, got %v", err)
		}
	})
	t.Run("zip64 offset sentinel is recognized", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, err := zw.Create(types.ScanBundleManifestName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		end := bytes.LastIndex(buf.Bytes(), []byte("PK\x05\x06"))
		if end < 0 {
			t.Fatal("zip end record not found")
		}
		binary.LittleEndian.PutUint32(buf.Bytes()[end+16:end+20], 0xffffffff)
		if _, err := readZipBundleManifest(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "zip64") {
			t.Fatalf("expected zip64 parsing error, got %v", err)
		}
	})
}

type scanBundleMaxBytesBody struct {
	done bool
}

func (b *scanBundleMaxBytesBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, &http.MaxBytesError{Limit: types.ScanBundleMaxUpload}
	}
	b.done = true
	return copy(p, []byte("null")), nil
}

func (b *scanBundleMaxBytesBody) Close() error { return nil }

func TestScanBundleUploadLimitReturns413(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/scans/import", &scanBundleMaxBytesBody{})
	rr := httptest.NewRecorder()
	s.handleImportScanBundle(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized scan bundle status = %d, want %d; body %s", rr.Code, http.StatusRequestEntityTooLarge, rr.Body.String())
	}
}

func TestDecodeScanBundleUploadStreamsZipToSpool(t *testing.T) {
	want := sampleBundleForTest()
	manifest, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create(types.ScanBundleManifestName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	spoolDir := t.TempDir()
	s := &Server{exportSpoolDir: spoolDir}
	req := httptest.NewRequest(http.MethodPost, "/api/scans/import", bytes.NewReader(buf.Bytes()))
	rr := httptest.NewRecorder()
	got, err := s.decodeScanBundleUpload(rr, req)
	if err != nil {
		t.Fatalf("decodeScanBundleUpload: %v", err)
	}
	if got.Scan.ID != want.Scan.ID {
		t.Fatalf("decoded scan id = %q, want %q", got.Scan.ID, want.Scan.ID)
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("scan bundle spool leaked %d temporary files", len(entries))
	}
}

func TestScanBundleImportSlot(t *testing.T) {
	s := &Server{scanBundleImportSlots: make(chan struct{}, 1)}
	release, ok := s.tryAcquireScanBundleImport()
	if !ok {
		t.Fatal("first scan bundle import was rejected")
	}
	if _, ok := s.tryAcquireScanBundleImport(); ok {
		t.Fatal("second concurrent scan bundle import was admitted")
	}
	release()
	if release, ok = s.tryAcquireScanBundleImport(); !ok {
		t.Fatal("scan bundle import was not admitted after release")
	} else {
		release()
	}
}

// TestScanBundleJSONRoundTrip proves a manifest survives encode/decode without
// losing any field, so a bundle exported as zip equals the JSON export.
func TestScanBundleJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(sampleBundleForTest())
	if err != nil {
		t.Fatal(err)
	}
	var decoded types.ScanBundle
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Format != types.ScanBundleFormat || decoded.FormatVersion != types.ScanBundleFormatVersion {
		t.Errorf("format markers lost: %+v", decoded)
	}
	if decoded.Scan.ID == "" || decoded.Scan.CreatedAt.IsZero() {
		t.Errorf("scan record lost: %+v", decoded.Scan)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].TemplateID == "" {
		t.Errorf("findings lost: %+v", decoded.Findings)
	}
}
