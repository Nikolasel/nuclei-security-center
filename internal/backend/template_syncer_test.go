package backend

import (
	"context"
	"fmt"
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
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestTemplateSyncStatusRedactsRepositorySecrets(t *testing.T) {
	s := &TemplateSyncer{config: TemplateSyncerConfig{Interval: 6 * time.Hour}}
	got := s.Status(store.TemplateSyncSource{
		Repo: "https://user:secret@example.test/catalog.git?token=hidden#fragment",
		Ref:  "v1.2.3",
	})
	if got.Repo != "https://example.test/catalog.git" {
		t.Fatalf("Repo = %q", got.Repo)
	}
	if !got.Enabled || got.Interval != "6h0m0s" || got.Ref != "v1.2.3" {
		t.Fatalf("unexpected status: %+v", got)
	}
	if got.RefSource != templateSyncChannelCustom {
		t.Fatalf("RefSource = %q, want custom", got.RefSource)
	}
	if got.DefaultRepo {
		t.Fatalf("DefaultRepo = true for a foreign repository")
	}
}

func TestTemplateSyncStatusChannelsAndDisabled(t *testing.T) {
	s := &TemplateSyncer{config: TemplateSyncerConfig{Interval: time.Hour}}
	for _, tc := range []struct {
		repo, ref, wantChannel   string
		wantDefault, wantEnabled bool
	}{
		{repo: "https://github.com/projectdiscovery/nuclei-templates.git", ref: "latest", wantChannel: templateSyncChannelStable, wantDefault: true, wantEnabled: true},
		{repo: "https://github.com/projectdiscovery/nuclei-templates.git", ref: "main", wantChannel: templateSyncChannelPreview, wantDefault: true, wantEnabled: true},
		{repo: "https://user:pw@github.com/projectdiscovery/nuclei-templates.git", ref: "v9.9.9", wantChannel: templateSyncChannelCustom, wantDefault: true, wantEnabled: true},
		{repo: "https://example.test/fork.git", ref: "dev-branch", wantChannel: templateSyncChannelCustom, wantEnabled: true},
		{repo: "", ref: "latest", wantChannel: "", wantEnabled: false},
	} {
		got := s.Status(store.TemplateSyncSource{Repo: tc.repo, Ref: tc.ref})
		if got.Enabled != tc.wantEnabled {
			t.Errorf("repo %q: Enabled = %v, want %v", tc.repo, got.Enabled, tc.wantEnabled)
		}
		if got.RefSource != tc.wantChannel {
			t.Errorf("repo %q ref %q: RefSource = %q, want %q", tc.repo, tc.ref, got.RefSource, tc.wantChannel)
		}
		if got.DefaultRepo != tc.wantDefault {
			t.Errorf("repo %q: DefaultRepo = %v, want %v", tc.repo, got.DefaultRepo, tc.wantDefault)
		}
		if got.Repo != SafeTemplateRepo(tc.repo) {
			t.Errorf("repo %q: sanitized = %q", tc.repo, got.Repo)
		}
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

// GET reports the DB-backed source (empty repo = disabled) even when the syncer
// is wired; POST queueing still works.
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
		config:  TemplateSyncerConfig{Interval: time.Hour},
		trigger: make(chan struct{}, 1),
	}
	rr = httptest.NewRecorder()
	s.handleGetTemplateSync(rr, httptest.NewRequest(http.MethodGet, "/api/templates/sync", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Fatalf("status without store = %d %s, want disabled", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "github.com") {
		t.Fatalf("status without store leaked a repository: %s", rr.Body.String())
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

// writeTemplateRepoFixture creates a local repository standing in for an
// upstream template catalog: one template file per id, an optional semver tag
// and an optional extra branch, both pointing at the single commit.
func writeTemplateRepoFixture(t *testing.T, ids []string, tag, branch string) (string, plumbing.Hash) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init fixture repository: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("open fixture worktree: %v", err)
	}
	for _, id := range ids {
		body := fmt.Sprintf("id: %s\ninfo:\n  name: %s\n  author: fixture\n  severity: medium\n  description: fixture\n", id, id)
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(body), 0o644); err != nil {
			t.Fatalf("write fixture template: %v", err)
		}
	}
	if err := wt.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		t.Fatalf("stage fixture templates: %v", err)
	}
	sig := &object.Signature{Name: "fixture", Email: "fixture@example.test", When: time.Now()}
	if _, err := wt.Commit("fixture catalog", &git.CommitOptions{Author: sig}); err != nil {
		t.Fatalf("commit fixture templates: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("read fixture HEAD: %v", err)
	}
	if tag != "" {
		if _, err := repo.CreateTag(tag, head.Hash(), &git.CreateTagOptions{Tagger: sig, Message: "fixture release"}); err != nil {
			t.Fatalf("tag fixture release: %v", err)
		}
	}
	if branch != "" {
		if err := repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), head.Hash())); err != nil {
			t.Fatalf("create fixture branch: %v", err)
		}
	}
	return dir, head.Hash()
}

// Two upstream repositories share one clone cache. After syncing the old
// repository, a switch to the new one must resolve against the new repository
// alone: fetch+force never deletes the previous repository's tags or
// remote-tracking refs, so without replacing the cache the old repo's higher
// semver tag would win `latest` and its leftover branch would win ref lookup.
func TestSyncTemplateRepositoryReplacesCacheOnRemoteSwitch(t *testing.T) {
	oldRepo, oldHead := writeTemplateRepoFixture(t, []string{"old-template"}, "v9.9.9", "legacy")
	newRepo, newHead := writeTemplateRepoFixture(t, []string{"new-template"}, "v1.0.0", "")
	dir := filepath.Join(t.TempDir(), "clone-cache")
	ctx := context.Background()
	log := testLogger()

	// Populate the cache from the old repository; its branch resolves too.
	commit, entries, _, err := syncTemplateRepository(ctx, dir, oldRepo, "latest", log)
	if err != nil {
		t.Fatalf("sync old repository: %v", err)
	}
	if commit != oldHead.String() || len(entries) != 1 || entries[0].ID != "old-template" {
		t.Fatalf("old catalog = commit %s entries %+v, want %s [old-template]", commit, entries, oldHead)
	}
	if commit, _, _, err := syncTemplateRepository(ctx, dir, oldRepo, "legacy", log); err != nil || commit != oldHead.String() {
		t.Fatalf("old repository branch legacy = %s err %v, want %s", commit, err, oldHead)
	}

	// Switch to the new repository: the old v9.9.9 tag must not win latest.
	commit, entries, _, err = syncTemplateRepository(ctx, dir, newRepo, "latest", log)
	if err != nil {
		t.Fatalf("sync new repository: %v", err)
	}
	if commit != newHead.String() || len(entries) != 1 || entries[0].ID != "new-template" {
		t.Fatalf("new catalog = commit %s entries %+v, want %s [new-template]", commit, entries, newHead)
	}

	// Refs only the old repository ever had must not resolve from stale refs.
	if _, _, _, err := syncTemplateRepository(ctx, dir, newRepo, "v9.9.9", log); err == nil {
		t.Fatal("the old repository's tag resolved against the new repository, want error")
	}
	if _, _, _, err := syncTemplateRepository(ctx, dir, newRepo, "legacy", log); err == nil {
		t.Fatal("the old repository's branch resolved against the new repository, want error")
	}
}
