package backend

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
)

func TestTemplateSyncStatusRedactsRepositorySecrets(t *testing.T) {
	s := &TemplateSyncer{config: TemplateSyncerConfig{
		Interval: 6 * time.Hour,
		Repo:     "https://user:secret@example.test/catalog.git?token=hidden#fragment",
		Ref:      "v1.2.3",
	}}
	got := s.Status()
	if got.Repo != "https://example.test/catalog.git" {
		t.Fatalf("Repo = %q", got.Repo)
	}
	if !got.Enabled || got.Interval != "6h0m0s" || got.Ref != "v1.2.3" {
		t.Fatalf("unexpected status: %+v", got)
	}
}

func TestTemplateSyncRequestsCoalesce(t *testing.T) {
	s := &TemplateSyncer{trigger: make(chan struct{}, 1)}
	s.RequestSync()
	s.RequestSync()
	if got := len(s.trigger); got != 1 {
		t.Fatalf("queued triggers = %d, want 1", got)
	}
}

func TestTemplateSyncHTTPDisabledAndQueued(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	s.handleGetTemplateSync(rr, httptest.NewRequest(http.MethodGet, "/api/templates/sync", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled status = %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	s.handleRequestTemplateSync(rr, httptest.NewRequest(http.MethodPost, "/api/templates/sync", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled request status = %d, want 503", rr.Code)
	}

	s.templateSyncer = &TemplateSyncer{
		config:  TemplateSyncerConfig{Interval: time.Hour, Repo: "https://example.test/catalog.git", Ref: "latest"},
		trigger: make(chan struct{}, 1),
	}
	rr = httptest.NewRecorder()
	s.handleGetTemplateSync(rr, httptest.NewRequest(http.MethodGet, "/api/templates/sync", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"enabled":true`) {
		t.Fatalf("enabled status without store = %d %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleRequestTemplateSync(rr, httptest.NewRequest(http.MethodPost, "/api/templates/sync", nil))
	if rr.Code != http.StatusAccepted || len(s.templateSyncer.trigger) != 1 {
		t.Fatalf("queued request = %d %s, trigger count %d", rr.Code, rr.Body.String(), len(s.templateSyncer.trigger))
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestReadTemplateCatalog(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "http", "example.yaml"), []byte("id: example\ninfo:\n  name: Example\n  severity: medium\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata.yml"), []byte("name: ignored\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, skipped, err := readTemplateCatalog(root, testLogger())
	if err != nil {
		t.Fatalf("readTemplateCatalog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if entries[0].ID != "example" || entries[0].Path != "http/example.yaml" || entries[0].YAML == "" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}
}

// A single malformed template is skipped-and-counted, not fatal: it must not
// pin the whole catalog stale (nuclei itself skips-and-warns). The refresh still
// fails closed only when *nothing* parses.
func TestReadTemplateCatalogSkipsBadTemplate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "good.yaml"), []byte("id: good\ninfo:\n  name: Good\n  severity: low\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bad.yaml"), []byte("id: bad\ninfo: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, skipped, err := readTemplateCatalog(root, testLogger())
	if err != nil {
		t.Fatalf("readTemplateCatalog: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "good" {
		t.Fatalf("entries = %+v, want only good", entries)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

// Two files claiming the same id: keep the first, skip the rest — a duplicate id
// anywhere in the tree must not fail the whole run.
func TestReadTemplateCatalogSkipsDuplicateID(t *testing.T) {
	root := t.TempDir()
	tpl := "id: dup\ninfo:\n  name: Dup\n  severity: low\n"
	if err := os.WriteFile(filepath.Join(root, "a.yaml"), []byte(tpl), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.yaml"), []byte(tpl), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, skipped, err := readTemplateCatalog(root, testLogger())
	if err != nil {
		t.Fatalf("readTemplateCatalog: %v", err)
	}
	if len(entries) != 1 || skipped != 1 {
		t.Fatalf("entries=%d skipped=%d, want 1 and 1", len(entries), skipped)
	}
}

// All-bad still fails closed: no good entry means the snapshot is suspect and
// the caller must not tombstone the entire existing catalog.
func TestReadTemplateCatalogFailsWhenNothingParses(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad.yaml"), []byte("id: bad\ninfo: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readTemplateCatalog(root, testLogger()); err == nil {
		t.Fatal("expected error when no templates parse")
	}
}

func TestSetTemplateRemoteHonorsConfigChanges(t *testing.T) {
	repo, err := git.PlainInit(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := setTemplateRemote(repo, "https://example.test/first.git"); err != nil {
		t.Fatalf("set initial remote: %v", err)
	}
	if err := setTemplateRemote(repo, "https://example.test/second.git"); err != nil {
		t.Fatalf("change remote: %v", err)
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		t.Fatal(err)
	}
	if got := remote.Config().URLs; len(got) != 1 || got[0] != "https://example.test/second.git" {
		t.Errorf("origin URLs = %v", got)
	}
}
