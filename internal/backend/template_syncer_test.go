package backend

import (
	"context"
	"errors"
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
		// `main` is the preview channel only on the community catalog: on any
		// other repository it is a custom ref (PR #344 review #15).
		{repo: "https://example.test/fork.git", ref: "main", wantChannel: templateSyncChannelCustom, wantEnabled: true},
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
func TestTemplateSnapshotReplacesCacheOnRemoteSwitch(t *testing.T) {
	oldRepo, oldHead := writeTemplateRepoFixture(t, []string{"old-template"}, "v9.9.9", "legacy")
	newRepo, newHead := writeTemplateRepoFixture(t, []string{"new-template"}, "v1.0.0", "")
	dir := filepath.Join(t.TempDir(), "clone-cache")
	ctx := context.Background()
	s := &TemplateSyncer{config: TemplateSyncerConfig{Interval: time.Hour, Dir: dir}, log: testLogger()}

	// Populate the cache from the old repository; its branch resolves too.
	commit, entries, _, err := s.templateSnapshot(ctx, dir, oldRepo, "latest")
	if err != nil {
		t.Fatalf("sync old repository: %v", err)
	}
	if commit != oldHead.String() || len(entries) != 1 || entries[0].ID != "old-template" {
		t.Fatalf("old catalog = commit %s entries %+v, want %s [old-template]", commit, entries, oldHead)
	}
	if commit, _, _, err := s.templateSnapshot(ctx, dir, oldRepo, "legacy"); err != nil || commit != oldHead.String() {
		t.Fatalf("old repository branch legacy = %s err %v, want %s", commit, err, oldHead)
	}

	// Switch to the new repository: the old v9.9.9 tag must not win latest.
	commit, entries, _, err = s.templateSnapshot(ctx, dir, newRepo, "latest")
	if err != nil {
		t.Fatalf("sync new repository: %v", err)
	}
	if commit != newHead.String() || len(entries) != 1 || entries[0].ID != "new-template" {
		t.Fatalf("new catalog = commit %s entries %+v, want %s [new-template]", commit, entries, newHead)
	}

	// Refs only the old repository ever had must not resolve from stale refs.
	if _, _, _, err := s.templateSnapshot(ctx, dir, newRepo, "v9.9.9"); err == nil {
		t.Fatal("the old repository's tag resolved against the new repository, want error")
	}
	if _, _, _, err := s.templateSnapshot(ctx, dir, newRepo, "legacy"); err == nil {
		t.Fatal("the old repository's branch resolved against the new repository, want error")
	}
}

// A source probe against a different repository must leave the sync cache —
// and every ref it holds — intact (PR #344 review #2): a cancelled dry run, a
// typo, or an unreachable candidate used to wipe the cache and force a full
// re-clone on the next sync. Foreign candidates are probed in a throwaway
// directory removed afterwards (PR #344 review A), so nothing persistent is
// ever re-pointed, and an expectCommit that still resolves skips the catalog
// walk (PR #344 review #6, the PUT's save-time probe reusing the dry run's
// result). The syncer has no store here, so every probe takes the throwaway
// path — the configured-repository reuse case is covered by
// TestNewProbeWorktree and the Postgres integration tests.
func TestTemplateSourceProbeLeavesSyncCacheIntact(t *testing.T) {
	oldRepo, oldHead := writeTemplateRepoFixture(t, []string{"old-template"}, "v9.9.9", "legacy")
	newRepo, newHead := writeTemplateRepoFixture(t, []string{"new-template"}, "v1.0.0", "")
	dir := filepath.Join(t.TempDir(), "clone-cache")
	ctx := context.Background()
	s := &TemplateSyncer{config: TemplateSyncerConfig{Interval: time.Hour, Dir: dir}, log: testLogger()}

	if _, _, _, err := s.templateSnapshot(ctx, s.config.Dir, oldRepo, "latest"); err != nil {
		t.Fatalf("sync old repository: %v", err)
	}

	commit, entries, _, err := s.resolveTemplateSnapshot(ctx, newRepo, "latest", "")
	if err != nil {
		t.Fatalf("probe new repository: %v", err)
	}
	if commit != newHead.String() || len(entries) != 1 || entries[0].ID != "new-template" {
		t.Fatalf("probe catalog = commit %s entries %+v, want %s [new-template]", commit, entries, newHead)
	}

	// The sync cache must still resolve only the old repository's refs.
	if commit, _, _, err := s.templateSnapshot(ctx, s.config.Dir, oldRepo, "legacy"); err != nil || commit != oldHead.String() {
		t.Fatalf("sync cache lost the old repository: %s %v, want %s", commit, err, oldHead)
	}
	if _, _, _, err := s.templateSnapshot(ctx, s.config.Dir, oldRepo, "v1.0.0"); err == nil {
		t.Fatal("the probed repository's tag resolved against the sync cache, want error")
	}

	// A second probe of the same candidate reuses the probe cache, and passing
	// the resolved commit skips the walk (no entries returned).
	commit, entries, _, err = s.resolveTemplateSnapshot(ctx, newRepo, "latest", newHead.String())
	if err != nil {
		t.Fatalf("verified probe: %v", err)
	}
	if commit != newHead.String() || entries != nil {
		t.Fatalf("verified probe = commit %s entries %v, want commit kept and walk skipped", commit, entries)
	}

	// A moved ref (or wrong expectCommit) walks the fresh snapshot instead.
	if _, entries, _, err := s.resolveTemplateSnapshot(ctx, newRepo, "latest", "0000000000000000000000000000000000000000"); err != nil || len(entries) != 1 {
		t.Fatalf("mismatched expectCommit = entries %+v err %v, want full walk", entries, err)
	}
}

// While a sync or another probe holds the worktree lock, a source probe fails
// fast instead of queueing behind it for up to a whole sync budget (PR #344
// review #5); the queued sync itself still waits.
func TestTemplateSourceProbeFailsFastWhenBusy(t *testing.T) {
	repo, _ := writeTemplateRepoFixture(t, []string{"t"}, "v1.0.0", "")
	s := &TemplateSyncer{config: TemplateSyncerConfig{Interval: time.Hour, Dir: filepath.Join(t.TempDir(), "clone-cache")}, log: testLogger()}
	s.worktree.Lock()
	defer s.worktree.Unlock()
	if _, _, _, err := s.resolveTemplateSnapshot(context.Background(), repo, "latest", ""); !errors.Is(err, errTemplateSyncBusy) {
		t.Fatalf("probe while busy = %v, want errTemplateSyncBusy", err)
	}
}

// The configured repository is probed in the real sync clone (under the
// caller-held worktree lock), any other candidate in a throwaway directory the
// cleanup removes (PR #344 review A/B): identity is compared on the sanitized
// URL, so rotated credentials still reuse the clone, and a store-less or
// empty-configured syncer never probes into persistent state.
func TestNewProbeWorktree(t *testing.T) {
	syncDir := filepath.Join(t.TempDir(), "clone-cache")

	dir, cleanup, err := newProbeWorktree("https://user:secret@example.test/catalog.git", syncDir, "https://example.test/catalog.git")
	if err != nil || dir != syncDir {
		t.Fatalf("configured candidate: dir %q err %v, want the sync clone", dir, err)
	}
	cleanup()

	// A foreign candidate (and an unconfigured/unknown one) gets a temp dir.
	for _, configured := range []string{"https://example.test/other.git", ""} {
		dir, cleanup, err := newProbeWorktree(configured, syncDir, "https://example.test/catalog.git")
		if err != nil || dir == syncDir || strings.HasPrefix(dir, syncDir) {
			t.Fatalf("foreign candidate (configured %q): dir %q err %v, want a throwaway directory", configured, dir, err)
		}
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("foreign candidate (configured %q): temp dir %s unavailable: %v", configured, dir, err)
		}
		cleanup()
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("foreign candidate (configured %q): temp dir %s survived cleanup", configured, dir)
		}
	}
}
