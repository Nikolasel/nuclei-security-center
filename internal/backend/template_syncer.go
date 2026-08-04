package backend

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/templates"
)

// syncTimeout bounds one refresh (clone/fetch + apply). It also defines
// "stale": a template_sync_runs row still 'running' after this long belongs to a
// crashed process and is reaped on the next tick.
const syncTimeout = 30 * time.Minute

// TemplateSyncerConfig controls the backend-owned mirror of the community
// template catalog. The working directory is a cache only: PostgreSQL holds the
// authoritative YAML after a successful run.
type TemplateSyncerConfig struct {
	Interval time.Duration
	Repo     string
	Ref      string
	Dir      string
}

// TemplateSyncer periodically fetches one upstream template repository and
// mirrors its YAML into the local catalog. It never exposes the clone to
// scanners; a later bundle-distribution slice will use the stored YAML.
type TemplateSyncer struct {
	store   *store.Store
	config  TemplateSyncerConfig
	log     *slog.Logger
	trigger chan struct{}
}

// TemplateSyncStatus is the safe, read-only configuration shown in the SPA.
// The cache directory is intentionally omitted, and credentials/query strings
// are removed from HTTP(S) repository URLs before they leave the backend.
type TemplateSyncStatus struct {
	Enabled         bool   `json:"enabled"`
	Interval        string `json:"interval,omitempty"`
	Repo            string `json:"repo,omitempty"`
	Ref             string `json:"ref,omitempty"`
	TemplatesCommit string `json:"templates_commit,omitempty"`
	TemplateCount   int    `json:"template_count"`
}

// NewTemplateSyncer validates and wires a catalog synchronizer. "latest" is a
// deliberate ref value: it resolves to the highest stable semver Git tag,
// avoiding a mutable default branch while retaining a zero-config setup.
func NewTemplateSyncer(st *store.Store, cfg TemplateSyncerConfig, log *slog.Logger) (*TemplateSyncer, error) {
	if cfg.Interval <= 0 {
		return nil, errors.New("template sync interval must be positive")
	}
	if strings.TrimSpace(cfg.Repo) == "" {
		return nil, errors.New("template sync repo is required")
	}
	if strings.TrimSpace(cfg.Ref) == "" {
		return nil, errors.New("template sync ref is required")
	}
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, errors.New("template sync directory is required")
	}
	return &TemplateSyncer{
		store: st, config: cfg, log: log.With("component", "template_syncer"),
		trigger: make(chan struct{}, 1),
	}, nil
}

// Start runs a refresh immediately, then repeats it on the configured cadence.
// A failed refresh is recorded and logged but does not take the backend down:
// the last successful catalog remains usable.
func (s *TemplateSyncer) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.config.Interval)
		defer ticker.Stop()
		s.sync(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sync(ctx)
			case <-s.trigger:
				s.sync(ctx)
			}
		}
	}()
}

// RequestSync queues one on-demand refresh. Repeated requests coalesce while a
// refresh is running or already queued, keeping the same single-writer behavior
// as periodic syncs without making the HTTP request wait for a large clone.
func (s *TemplateSyncer) RequestSync() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Status returns the non-secret configuration needed by the Sync tab.
func (s *TemplateSyncer) Status() TemplateSyncStatus {
	return TemplateSyncStatus{
		Enabled: true, Interval: s.config.Interval.String(),
		Repo: safeTemplateRepo(s.config.Repo), Ref: s.config.Ref,
	}
}

func safeTemplateRepo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (s *TemplateSyncer) sync(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	// A crash mid-sync leaves a template_sync_runs row stuck at 'running'
	// forever; reap any run older than our own timeout before starting a new one
	// so the runs view reflects reality.
	if n, err := s.store.ReapStaleTemplateSyncRuns(ctx, syncTimeout); err != nil {
		s.log.Warn("reap stale template sync runs", "err", err)
	} else if n > 0 {
		s.log.Warn("reaped stale template sync runs", "count", n)
	}
	run, err := s.store.StartTemplateSync(ctx)
	if err != nil {
		s.log.Error("start template sync", "err", err)
		return
	}
	ref, entries, skipped, err := syncTemplateRepository(ctx, s.config, s.log)
	if err != nil {
		if ferr := s.store.FailTemplateSync(ctx, run.ID, err); ferr != nil {
			s.log.Error("record failed template sync", "sync_err", err, "record_err", ferr)
			return
		}
		s.log.Error("template sync failed", "err", err)
		return
	}
	stats, err := s.store.ApplyUpstreamTemplates(ctx, run.ID, ref, entries, skipped)
	if err != nil {
		if ferr := s.store.FailTemplateSync(ctx, run.ID, err); ferr != nil {
			s.log.Error("record failed template sync", "sync_err", err, "record_err", ferr)
			return
		}
		s.log.Error("apply template catalog", "err", err)
		return
	}
	// actor_type=system keeps this in the same event=audit shape every other
	// mutation emits (see logSystemAudit) — a headless job, not a user.
	s.log.Info("template sync complete", "event", "audit", "event_id", eventConfigChanged,
		"action", "templates.sync", "object_type", "template_sync", "object_id", run.ID,
		"actor_subject", "system", "actor_type", "system", "ref", ref,
		"added", stats.Added, "updated", stats.Updated, "removed", stats.Removed, "skipped", stats.Skipped)
}

func syncTemplateRepository(ctx context.Context, cfg TemplateSyncerConfig, log *slog.Logger) (string, []store.Template, int, error) {
	repo, err := openOrCloneTemplateRepo(ctx, cfg.Dir, cfg.Repo)
	if err != nil {
		return "", nil, 0, err
	}
	commit, err := checkoutTemplateRef(repo, cfg.Ref)
	if err != nil {
		return "", nil, 0, err
	}
	entries, skipped, err := readTemplateCatalog(cfg.Dir, log)
	if err != nil {
		return "", nil, 0, err
	}
	return commit.String(), entries, skipped, nil
}

func openOrCloneTemplateRepo(ctx context.Context, dir, remote string) (*git.Repository, error) {
	repo, err := git.PlainOpen(dir)
	if err == nil {
		if err := setTemplateRemote(repo, remote); err != nil {
			return nil, err
		}
		err = repo.FetchContext(ctx, &git.FetchOptions{RemoteName: "origin", Force: true, Tags: git.AllTags})
		if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
			return nil, fmt.Errorf("fetch template repository: %w", err)
		}
		return repo, nil
	}
	if !errors.Is(err, git.ErrRepositoryNotExists) {
		return nil, fmt.Errorf("open template repository: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return nil, fmt.Errorf("create template sync parent: %w", err)
	}
	repo, err = git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{URL: remote, Tags: git.AllTags})
	if err != nil {
		return nil, fmt.Errorf("clone template repository: %w", err)
	}
	return repo, nil
}

// setTemplateRemote makes TEMPLATE_SYNC_REPO an actual runtime setting even
// when a cache directory already contains an older clone. Without this, an
// operator changing the variable would quietly continue fetching the old repo.
func setTemplateRemote(repo *git.Repository, remote string) error {
	cfg, err := repo.Config()
	if err != nil {
		return fmt.Errorf("read template repository config: %w", err)
	}
	if cfg.Remotes == nil {
		cfg.Remotes = make(map[string]*config.RemoteConfig)
	}
	current, ok := cfg.Remotes["origin"]
	if !ok {
		cfg.Remotes["origin"] = &config.RemoteConfig{Name: "origin", URLs: []string{remote}}
	} else if len(current.URLs) != 1 || current.URLs[0] != remote {
		current.URLs = []string{remote}
	}
	if err := repo.SetConfig(cfg); err != nil {
		return fmt.Errorf("set template repository remote: %w", err)
	}
	return nil
}

func checkoutTemplateRef(repo *git.Repository, ref string) (plumbing.Hash, error) {
	var hash plumbing.Hash
	var err error
	if ref == "latest" {
		hash, err = latestReleaseCommit(repo)
	} else {
		hash, err = resolveTemplateRef(repo, ref)
	}
	if err != nil {
		return plumbing.ZeroHash, err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("open template worktree: %w", err)
	}
	if err := wt.Checkout(&git.CheckoutOptions{Hash: hash, Force: true}); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("checkout template ref: %w", err)
	}
	return hash, nil
}

func resolveTemplateRef(repo *git.Repository, ref string) (plumbing.Hash, error) {
	// refs/remotes/origin/<ref> MUST come before the bare ref. ResolveRevision
	// expands a bare name via RefRevParseRules, where refs/heads/<ref> matches
	// before refs/remotes/<ref>; since FetchContext only advances
	// refs/remotes/origin/*, the clone-time local branch is never updated, so a
	// bare "main" would silently pin the catalog to the first clone forever.
	// Trying the remote-tracking ref first makes branch refs track upstream.
	for _, candidate := range []plumbing.Revision{
		plumbing.Revision("refs/remotes/origin/" + ref),
		plumbing.Revision("refs/tags/" + ref),
		plumbing.Revision(ref),
	} {
		hash, err := repo.ResolveRevision(candidate)
		if err == nil {
			return dereferenceAnnotatedTag(repo, *hash)
		}
	}
	return plumbing.ZeroHash, fmt.Errorf("resolve template ref %q", ref)
}

func dereferenceAnnotatedTag(repo *git.Repository, hash plumbing.Hash) (plumbing.Hash, error) {
	tag, err := repo.TagObject(hash)
	if err == nil {
		return tag.Target, nil
	}
	if errors.Is(err, plumbing.ErrObjectNotFound) {
		return hash, nil
	}
	return plumbing.ZeroHash, err
}

var semverTag = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

func latestReleaseCommit(repo *git.Repository) (plumbing.Hash, error) {
	tags, err := repo.Tags()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("list template tags: %w", err)
	}
	type candidate struct {
		name    string
		version [3]int
		hash    plumbing.Hash
	}
	var releases []candidate
	err = tags.ForEach(func(ref *plumbing.Reference) error {
		match := semverTag.FindStringSubmatch(ref.Name().Short())
		if match == nil {
			return nil
		}
		var version [3]int
		for i := range version {
			version[i], _ = strconv.Atoi(match[i+1])
		}
		hash, err := dereferenceAnnotatedTag(repo, ref.Hash())
		if err != nil {
			return err
		}
		releases = append(releases, candidate{name: ref.Name().Short(), version: version, hash: hash})
		return nil
	})
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("read template tags: %w", err)
	}
	if len(releases) == 0 {
		return plumbing.ZeroHash, errors.New("template repository has no stable semver tags for ref latest")
	}
	sort.Slice(releases, func(i, j int) bool {
		for x := range releases[i].version {
			if releases[i].version[x] != releases[j].version[x] {
				return releases[i].version[x] > releases[j].version[x]
			}
		}
		return releases[i].name > releases[j].name
	})
	return releases[0].hash, nil
}

// readTemplateCatalog walks the checked-out tree and extracts every Nuclei
// template. A single malformed template (bad YAML, multi-doc, a duplicate id)
// is skipped and logged rather than failing the whole refresh — nuclei itself
// skips-and-warns, and one stray file in the ~10k-file community tree must not
// pin the catalog stale. The returned count of skipped files is recorded on the
// sync run. Fail-closed still applies to the snapshot as a whole: if nothing
// parses, the caller aborts rather than tombstoning the entire catalog.
func readTemplateCatalog(root string, log *slog.Logger) ([]store.Template, int, error) {
	var entries []store.Template
	skipped := 0
	seen := make(map[string]string) // id -> first path that claimed it
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		meta, err := templates.Parse(rel, body)
		if errors.Is(err, templates.ErrNotTemplate) {
			return nil
		}
		if err != nil {
			skipped++
			log.Warn("skipping malformed template", "path", rel, "err", err)
			return nil
		}
		if first, dup := seen[meta.ID]; dup {
			skipped++
			log.Warn("skipping duplicate template id", "id", meta.ID, "path", rel, "kept", first)
			return nil
		}
		seen[meta.ID] = rel
		entries = append(entries, store.Template{
			ID: meta.ID, Path: meta.Path, YAML: meta.YAML, ContentSHA256: meta.ContentSHA256,
			Name: meta.Name, Author: meta.Author, Severity: meta.Severity,
			Description: meta.Description, Tags: meta.Tags,
		})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if len(entries) == 0 {
		return nil, 0, errors.New("template repository contained no Nuclei templates")
	}
	return entries, skipped, nil
}
