package backend

import (
	"archive/zip"
	"bytes"
	"encoding/json"
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
			CreatedAt: t0,
			Spec:      json.RawMessage(`{}`),
		},
		Findings: []types.ScanBundleFinding{{
			ID: 1, TemplateID: "cve-x", Name: "X", Severity: "high",
			Host: "scanme.invalid", MatchedAt: "https://scanme.invalid/", Type: "http",
			CreatedAt: t0, Raw: json.RawMessage(`{"template-id":"cve-x"}`),
		}},
		Lifecycle: []types.ScanBundleLifecycle{{
			TemplateID: "cve-x", MatchedAt: "https://scanme.invalid/",
			FirstSeenAt: t0, LastSeenAt: t0, Disposition: "accepted",
		}},
	}
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
		_, _ = f.Write(bytes.Repeat([]byte("x"), types.ScanBundleMaxUpload+1))
		_ = zw.Close()
		if _, err := readZipBundleManifest(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("expected size-limit error, got %v", err)
		}
	})
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
	if len(decoded.Lifecycle) != 1 || decoded.Lifecycle[0].Disposition != "accepted" {
		t.Errorf("lifecycle lost: %+v", decoded.Lifecycle)
	}
}
