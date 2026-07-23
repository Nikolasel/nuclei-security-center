package scanner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// bundleFile is one file to place in a test bundle tarball.
type bundleFile struct {
	name    string // tar entry path
	content string
}

// makeBundle builds a gzipped tar from the given files plus a manifest. If
// manifest is nil, a correct one is derived from templateFiles; pass a manifest
// to inject a mismatch. extraTyped adds a raw header (e.g. a symlink) for the
// negative tests.
func makeBundle(t *testing.T, files []bundleFile, manifest *types.TemplateBundleManifest, extra func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if manifest == nil {
		var entries []types.TemplateBundleEntry
		for _, f := range files {
			sum := sha256.Sum256([]byte(f.content))
			entries = append(entries, types.TemplateBundleEntry{
				ID: f.name, Path: f.name, SHA256: hex.EncodeToString(sum[:]),
			})
		}
		manifest = &types.TemplateBundleManifest{Digest: types.BundleDigest(entries), Templates: entries}
	}
	mBytes, _ := json.Marshal(manifest)
	writeTar(t, tw, manifestName, string(mBytes))
	for _, f := range files {
		writeTar(t, tw, f.name, f.content)
	}
	if extra != nil {
		extra(tw)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeTar(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
}

func newTestBundleStore(t *testing.T) *bundleStore {
	t.Helper()
	b, err := newBundleStore(filepath.Join(t.TempDir(), "_bundle"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundleApplyAndActivate(t *testing.T) {
	b := newTestBundleStore(t)
	files := []bundleFile{
		{"http/cves/a.yaml", "id: a\n"},
		{"custom/b.yaml", "id: b\n"},
	}
	data := makeBundle(t, files, nil, nil)

	status, err := b.apply(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if status.TemplateCount != 2 {
		t.Errorf("count = %d, want 2", status.TemplateCount)
	}
	if status.TemplatesCommit == "" || status.TemplatesCommit != b.activeDigest() {
		t.Errorf("activeDigest %q != status %q", b.activeDigest(), status.TemplatesCommit)
	}
	// Files landed in the active tree.
	if got, _ := os.ReadFile(filepath.Join(b.activePath(), "http/cves/a.yaml")); string(got) != "id: a\n" {
		t.Errorf("active file content = %q", got)
	}
}

func TestBundleApplyReplacesActive(t *testing.T) {
	b := newTestBundleStore(t)
	first := makeBundle(t, []bundleFile{{"http/a.yaml", "id: a\n"}}, nil, nil)
	if _, err := b.apply(bytes.NewReader(first)); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second := makeBundle(t, []bundleFile{{"http/c.yaml", "id: c\n"}}, nil, nil)
	if _, err := b.apply(bytes.NewReader(second)); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	// The old file is gone (atomic replace, not a merge).
	if _, err := os.Stat(filepath.Join(b.activePath(), "http/a.yaml")); !os.IsNotExist(err) {
		t.Errorf("old bundle file should be gone after replace")
	}
	if _, err := os.Stat(filepath.Join(b.activePath(), "http/c.yaml")); err != nil {
		t.Errorf("new bundle file missing: %v", err)
	}
}

func TestBundleActiveDigestPersists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "_bundle")
	b, _ := newBundleStore(dir)
	data := makeBundle(t, []bundleFile{{"http/a.yaml", "id: a\n"}}, nil, nil)
	status, err := b.apply(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	// A fresh store over the same dir recovers the active digest (survives restart).
	b2, _ := newBundleStore(dir)
	if b2.activeDigest() != status.TemplatesCommit {
		t.Errorf("recovered digest %q != %q", b2.activeDigest(), status.TemplatesCommit)
	}
}

func TestBundleApplyRejects(t *testing.T) {
	good := []bundleFile{{"http/a.yaml", "id: a\n"}}

	t.Run("hash mismatch", func(t *testing.T) {
		// Manifest claims a hash that doesn't match the file bytes.
		m := &types.TemplateBundleManifest{Templates: []types.TemplateBundleEntry{
			{ID: "a", Path: "http/a.yaml", SHA256: "deadbeef"},
		}}
		m.Digest = types.BundleDigest(m.Templates)
		assertInvalid(t, makeBundle(t, good, m, nil))
	})

	t.Run("digest mismatch", func(t *testing.T) {
		sum := sha256.Sum256([]byte("id: a\n"))
		m := &types.TemplateBundleManifest{Digest: "wrongdigest", Templates: []types.TemplateBundleEntry{
			{ID: "a", Path: "http/a.yaml", SHA256: hex.EncodeToString(sum[:])},
		}}
		assertInvalid(t, makeBundle(t, good, m, nil))
	})

	t.Run("empty manifest", func(t *testing.T) {
		m := &types.TemplateBundleManifest{Digest: types.BundleDigest(nil)}
		assertInvalid(t, makeBundle(t, nil, m, nil))
	})

	t.Run("missing file", func(t *testing.T) {
		// Manifest lists a template whose file isn't in the tar.
		sum := sha256.Sum256([]byte("id: x\n"))
		m := &types.TemplateBundleManifest{Templates: []types.TemplateBundleEntry{
			{ID: "x", Path: "http/missing.yaml", SHA256: hex.EncodeToString(sum[:])},
		}}
		m.Digest = types.BundleDigest(m.Templates)
		assertInvalid(t, makeBundle(t, nil, m, nil))
	})

	t.Run("zip slip", func(t *testing.T) {
		data := makeBundle(t, good, nil, func(tw *tar.Writer) {
			writeTar(t, tw, "../escape.yaml", "pwned")
		})
		assertInvalid(t, data)
	})

	t.Run("symlink entry", func(t *testing.T) {
		data := makeBundle(t, good, nil, func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: "link.yaml", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
		})
		assertInvalid(t, data)
	})

	t.Run("not gzip", func(t *testing.T) {
		assertInvalid(t, []byte("this is not a gzip stream"))
	})
}

func TestBundleLockTemplatesResolvesIDsAndRejectsDrift(t *testing.T) {
	b := newTestBundleStore(t)
	files := []bundleFile{
		{"http/a.yaml", "id: a\n"},
		{"custom/b.yaml", "id: b\n"},
	}
	entries := []types.TemplateBundleEntry{
		{ID: "a", Path: files[0].name, SHA256: contentHash(files[0].content)},
		{ID: "b", Path: files[1].name, SHA256: contentHash(files[1].content)},
	}
	manifest := &types.TemplateBundleManifest{Digest: types.BundleDigest(entries), Templates: entries}
	if _, err := b.apply(bytes.NewReader(makeBundle(t, files, manifest, nil))); err != nil {
		t.Fatal(err)
	}

	paths, unlock, err := b.lockTemplates([]string{"b", "a"}, manifest.Digest)
	if err != nil {
		t.Fatalf("lockTemplates: %v", err)
	}
	unlock()
	if len(paths) != 2 ||
		paths[0] != filepath.Join(b.activePath(), "custom/b.yaml") ||
		paths[1] != filepath.Join(b.activePath(), "http/a.yaml") {
		t.Errorf("resolved paths = %v", paths)
	}

	if _, _, err := b.lockTemplates([]string{"missing-b", "missing-a"}, manifest.Digest); !errors.Is(err, ErrMissingTemplates) ||
		!strings.Contains(err.Error(), "missing-a, missing-b") {
		t.Errorf("missing-template error = %v", err)
	}
	if _, _, err := b.lockTemplates([]string{"a"}, "old-digest"); err == nil ||
		!strings.Contains(err.Error(), "commit mismatch") {
		t.Errorf("commit mismatch error = %v", err)
	}
}

func TestBundleActivationRefusedWhileScanHoldsTree(t *testing.T) {
	b := newTestBundleStore(t)
	first := makeBundle(t, []bundleFile{{"http/a.yaml", "id: a\n"}}, nil, nil)
	status, err := b.apply(bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	_, unlock, err := b.lockTemplates([]string{"http/a.yaml"}, status.TemplatesCommit)
	if err != nil {
		t.Fatal(err)
	}

	second := makeBundle(t, []bundleFile{{"http/b.yaml", "id: b\n"}}, nil, nil)
	if _, err := b.apply(bytes.NewReader(second)); !errors.Is(err, ErrBundleBusy) {
		t.Fatalf("apply while tree is locked = %v, want ErrBundleBusy", err)
	}
	unlock()
	if b.activeDigest() != status.TemplatesCommit {
		t.Errorf("busy apply changed active digest")
	}
}

func TestScanStartingDuringActivationQueues(t *testing.T) {
	b := newTestBundleStore(t)
	data := makeBundle(t, []bundleFile{{"http/a.yaml", "id: a\n"}}, nil, nil)
	status, err := b.apply(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	// Hold the activation lock directly to make the otherwise tiny rename window
	// deterministic. lockTemplates must wait, not fail or observe partial state.
	b.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, unlock, err := b.lockTemplates([]string{"http/a.yaml"}, status.TemplatesCommit)
		if err == nil {
			unlock()
		}
		done <- err
	}()
	select {
	case err := <-done:
		b.mu.Unlock()
		t.Fatalf("scan did not queue during activation: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	b.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("queued scan failed after activation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued scan did not resume")
	}
}

func contentHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// assertInvalid asserts apply fails with ErrInvalidBundle and leaves no active
// bundle (fail-closed: a rejected push never becomes active).
func assertInvalid(t *testing.T, data []byte) {
	t.Helper()
	b := newTestBundleStore(t)
	if _, err := b.apply(bytes.NewReader(data)); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("err = %v, want ErrInvalidBundle", err)
	}
	if b.activeDigest() != "" {
		t.Errorf("a rejected bundle must not become active")
	}
}
