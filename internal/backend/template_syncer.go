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
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/templates"
)

// syncTimeout bounds one refresh (clone/fetch + apply). It also defines
// "stale": a template_sync_runs row still 'running' after this long belongs to a
// crashed process and is reaped on the next tick. The source-switch probe
// (preview / resolve at save time, #343) uses the shorter probeTimeout instead:
// probes share the worktree lock with syncs, so an unbounded probe would hold
// admin HTTP requests open for the whole sync budget (PR #344 review).
const syncTimeout = 30 * time.Minute

// probeTimeout bounds one source-switch probe (preview or save-time
// validation). Generous enough for a first clone of the full community catalog
// on a modest link; short enough that a wedged probe fails instead of hanging
// past load balancers' idle timeouts (PR #344 review).
const probeTimeout = 10 * time.Minute

// errTemplateSyncBusy reports that another sync or probe holds the worktree
// lock. Source probes fail fast with 503 instead of queueing behind a running
// sync for up to half an hour (PR #344 review); the sync loop itself waits.
var errTemplateSyncBusy = errors.New("a template sync or source probe is already running")

// errTemplateRepoUnreachable wraps transport-level fetch/clone failures. The
// raw go-git error can name internal hosts (dial errors leak network topology,
// PR #344 review #7), so HTTP responses carry a generic message while the full
// error is logged server-side.
var errTemplateRepoUnreachable = errors.New("template repository is unreachable")

// TemplateSyncerConfig controls the backend-owned mirror of the community
// template catalog. The working directory is a cache only: PostgreSQL holds the
// authoritative YAML after a successful run. Repo and ref are deliberately not
// here — they live on the app_settings singleton (#343) so admins can switch
// sources at runtime; the syncer reads them from the store at the start of
// every run.
type TemplateSyncerConfig struct {
	Interval time.Duration
	Dir      string
}

// TemplateSyncer periodically fetches one upstream template repository and
// mirrors its YAML into the local catalog. It never exposes the clone to
// scanners; a later bundle-distribution slice will use the stored YAML. The
// goroutine always runs: an empty stored repository is the runtime
// "upstream sync disabled" state, checked per run.
type TemplateSyncer struct {
	store   *store.Store
	config  TemplateSyncerConfig
	log     *slog.Logger
	trigger chan struct{}
	// worktree guards the clone cache's fetch/checkout against a concurrent
	// source probe (#343); both come from the HTTP handler and the sync loop.
	worktree sync.Mutex
}

// TemplateSyncStatus is the safe, read-only configuration shown in the SPA.
// The cache directory is intentionally omitted, and credentials/query strings
// are removed from HTTP(S) repository URLs before they leave the backend.
// RefSource is the channel label derived from the stored repo/ref (stable =
// latest, preview = main on the community catalog, custom = anything else);
// DefaultRepo reports whether the sanitized repository is the ProjectDiscovery
// community catalog; SourceUpdatedAt/By name the admin who last switched the
// source (unset while it has only ever been seeded from the environment).
type TemplateSyncStatus struct {
	Enabled         bool       `json:"enabled"`
	Interval        string     `json:"interval,omitempty"`
	Repo            string     `json:"repo,omitempty"`
	Ref             string     `json:"ref,omitempty"`
	RefSource       string     `json:"ref_source,omitempty"`
	DefaultRepo     bool       `json:"default_repo"`
	TemplatesCommit string     `json:"templates_commit,omitempty"`
	TemplateCount   int        `json:"template_count"`
	SourceUpdatedAt *time.Time `json:"source_updated_at,omitempty"`
	SourceUpdatedBy string     `json:"source_updated_by,omitempty"`
}

// templateSyncChannels are the ref-channel labels exposed by the status and
// preview APIs. `latest` keeps its magic meaning (highest stable semver tag)
// for any repository; `main` is the ProjectDiscovery preview channel.
const (
	templateSyncChannelStable  = "stable"
	templateSyncChannelPreview = "preview"
	templateSyncChannelCustom  = "custom"
)

// templateSyncChannel maps a repo/ref pair to its channel label. The label is
// purely derived so it cannot drift from what a sync would do: `latest` keeps
// its magic meaning (highest stable semver tag) for any repository, while
// `main` is the ProjectDiscovery preview channel only on the community catalog
// — on any other repository `main` is just a custom ref (PR #344 review #15).
func templateSyncChannel(repo, ref string) string {
	switch ref {
	case "latest":
		return templateSyncChannelStable
	case "main":
		if isDefaultTemplateRepo(repo) {
			return templateSyncChannelPreview
		}
		return templateSyncChannelCustom
	default:
		return templateSyncChannelCustom
	}
}

// NewTemplateSyncer wires a catalog synchronizer. The repository and ref come
// from the store (seeded from TEMPLATE_SYNC_REPO / TEMPLATE_SYNC_REF by the
// entrypoint), so they are validated per run rather than here.
func NewTemplateSyncer(st *store.Store, cfg TemplateSyncerConfig, log *slog.Logger) (*TemplateSyncer, error) {
	if cfg.Interval <= 0 {
		return nil, errors.New("template sync interval must be positive")
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

// Status returns the non-secret configuration needed by the Sync tab, built
// from the DB-backed source (#343): an empty repository means upstream sync is
// disabled, and credentials never leave the backend.
func (s *TemplateSyncer) Status(src store.TemplateSyncSource) TemplateSyncStatus {
	enabled := strings.TrimSpace(src.Repo) != ""
	st := TemplateSyncStatus{
		Enabled:  enabled,
		Interval: s.config.Interval.String(),
		Repo:     SafeTemplateRepo(src.Repo),
		Ref:      src.Ref,
	}
	if enabled {
		st.RefSource = templateSyncChannel(src.Repo, src.Ref)
	}
	st.DefaultRepo = isDefaultTemplateRepo(src.Repo)
	return st
}

// SafeTemplateRepo returns the credential-free form of a repository URL
// (userinfo + query + fragment stripped) — the only repository shape the API
// and logs expose. Package-level so the entrypoint can log seeded and drifted
// source values without leaking embedded credentials.
func SafeTemplateRepo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// isDefaultTemplateRepo reports whether the stored repository (after
// sanitization) is the ProjectDiscovery community catalog, so the UI can offer
// the Stable/Preview channel choice for it.
func isDefaultTemplateRepo(raw string) bool {
	return strings.TrimSpace(raw) != "" && SafeTemplateRepo(strings.TrimSpace(raw)) == defaultTemplateRepo
}

func (s *TemplateSyncer) sync(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	// A crash mid-sync leaves a template_sync_runs row stuck at 'running'
	// forever; reap any run older than our own timeout before starting a new one
	// so the runs view reflects reality. This also reaps runs left behind
	// before the source was switched to an empty repo (disabled).
	if n, err := s.store.ReapStaleTemplateSyncRuns(ctx, syncTimeout); err != nil {
		s.log.Warn("reap stale template sync runs", "err", err)
	} else if n > 0 {
		s.log.Warn("reaped stale template sync runs", "count", n)
	}
	// The DB is the source of record for repo/ref (#343): each run resolves the
	// effective configuration fresh, so periodic, on-demand, and post-switch
	// runs all observe the same current value, and multiple backend replicas
	// stay consistent.
	src, err := s.store.GetTemplateSyncSource(ctx)
	if err != nil {
		s.log.Error("read template sync source", "err", err)
		return
	}
	if strings.TrimSpace(src.Repo) == "" {
		s.log.Debug("template sync skipped: upstream repository is empty (disabled)")
		return
	}
	ref := strings.TrimSpace(src.Ref)
	if ref == "" {
		// The seed always pairs a repo with a ref; an admin update validates the
		// ref. Treat a degraded row as the documented default rather than
		// failing every run.
		ref = "latest"
	}
	s.run(ctx, strings.TrimSpace(src.Repo), ref)
}

// run performs one full refresh against the given source: probe the clone
// cache (under the worktree lock, shared with source probes #343), then apply
// the snapshot to the store. The run row records the sanitized repository and
// configured ref it actually read, so the Sync view can show source switches
// (PR #344 review #8).
func (s *TemplateSyncer) run(ctx context.Context, repo, ref string) {
	run, err := s.store.StartTemplateSync(ctx, SafeTemplateRepo(repo), ref)
	if err != nil {
		s.log.Error("start template sync", "err", err)
		return
	}
	s.worktree.Lock()
	commit, entries, skipped, err := s.templateSnapshot(ctx, s.config.Dir, repo, ref)
	s.worktree.Unlock()
	if err != nil {
		if ferr := s.store.FailTemplateSync(ctx, run.ID, err); ferr != nil {
			s.log.Error("record failed template sync", "sync_err", err, "record_err", ferr)
			return
		}
		s.log.Error("template sync failed", "err", err)
		return
	}
	stats, err := s.store.ApplyUpstreamTemplates(ctx, run.ID, commit, entries, skipped)
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
		"actor_subject", "system", "actor_type", "system", "repo", SafeTemplateRepo(repo), "ref", ref,
		"added", stats.Added, "updated", stats.Updated, "restored", stats.Restored,
		"removed", stats.Removed, "skipped", stats.Skipped)
}

// templateSnapshot fetches and checks out repo/ref in the given clone-cache
// directory and reads its catalog. dir is the sync cache for real runs (where
// openOrCloneTemplateRepo may legitimately replace the cache when the stored
// source changed) and the probe cache for source probes.
func (s *TemplateSyncer) templateSnapshot(ctx context.Context, dir, repo, ref string) (string, []store.Template, int, error) {
	r, err := openOrCloneTemplateRepo(ctx, dir, repo, s.log)
	if err != nil {
		return "", nil, 0, err
	}
	commit, err := checkoutTemplateRef(r, ref)
	if err != nil {
		return "", nil, 0, err
	}
	entries, skipped, err := readTemplateCatalog(dir, s.log)
	if err != nil {
		return "", nil, 0, err
	}
	return commit.String(), entries, skipped, nil
}

// PreviewSource resolves a candidate repo/ref in the probe cache — fetch,
// checkout, and catalog walk — without writing anything to the store (#343).
// The candidate snapshot is diffed against the stored upstream catalog the same
// way ApplyUpstreamTemplates reconciles, so the returned counts are what the
// real sync would record: added (unknown ids), changed (different content),
// restored (a tombstoned id the snapshot brings back — counted separately from
// content changes, PR #344 review #4), removed (active ids absent from the
// snapshot), plus the exact template sets whose stored membership would be
// tombstoned and the scan policies/schedules that resolve them. A failed
// resolve (unreachable repo, unknown ref) or a snapshot that would shadow a
// custom template is the caller's validation error; the dry run must refuse
// exactly what the queued sync would refuse after the source is stored.
func (s *TemplateSyncer) PreviewSource(ctx context.Context, repo, ref string) (store.TemplateSyncPreview, error) {
	preview := store.TemplateSyncPreview{
		Repo: SafeTemplateRepo(repo), Ref: ref,
		RefSource: templateSyncChannel(repo, ref), DefaultRepo: isDefaultTemplateRepo(repo),
		AffectedSets:      []store.TemplateSetMemberLoss{},
		RegainedSets:      []store.TemplateSetMemberGain{},
		AffectedPolicies:  []store.TemplateSetUser{},
		AffectedSchedules: []store.TemplateSetUser{},
	}
	commit, entries, skipped, err := s.resolveTemplateSnapshot(ctx, repo, ref, "")
	if err != nil {
		return preview, err
	}
	preview.Commit = commit
	preview.Skipped = skipped
	states, err := s.store.UpstreamTemplateStates(ctx)
	if err != nil {
		return preview, err
	}
	incoming := make(map[string]struct{}, len(entries))
	var restored []string
	for _, t := range entries {
		incoming[t.ID] = struct{}{}
		old, found := states[t.ID]
		switch {
		case !found:
			preview.Added++
		case old.Availability != "active":
			preview.Restored++
			restored = append(restored, t.ID)
		case old.Hash != t.ContentSHA256:
			preview.Changed++
		}
	}
	var removed []string
	for id, st := range states {
		if _, ok := incoming[id]; ok || st.Availability != "active" {
			continue
		}
		removed = append(removed, id)
	}
	preview.Removed = len(removed)
	if len(removed) > 0 {
		losses, err := s.store.TemplateSetsLosingMembers(ctx, removed)
		if err != nil {
			return preview, err
		}
		preview.AffectedSets = losses
		setIDs := make([]string, 0, len(losses))
		for _, l := range losses {
			setIDs = append(setIDs, l.ID)
		}
		users, err := s.store.TemplateSetUsers(ctx, setIDs)
		if err != nil {
			return preview, err
		}
		for _, u := range users {
			if u.Kind == "schedule" {
				preview.AffectedSchedules = append(preview.AffectedSchedules, u)
			} else {
				preview.AffectedPolicies = append(preview.AffectedPolicies, u)
			}
		}
	}
	if len(restored) > 0 {
		gains, err := s.store.TemplateSetsRegainingMembers(ctx, restored, removed)
		if err != nil {
			return preview, err
		}
		// Only sets the candidate makes fully scannable again — every
		// unavailable member restored, no active member removed (PR #344
		// review). Sets that regain just part of their membership stay
		// refused at dispatch and are reported only via the Restored count.
		preview.RegainedSets = gains
	}
	return preview, nil
}

// probeDir is the second clone cache source probes run against (PR #344 review
// #2). Preview and save-time validation never touch the real sync cache: a
// cancelled dry run, a typo, or an unreachable candidate used to wipe ~1 GB of
// fetched history and force a full re-clone on the next sync. The probe cache
// converges on the last-probed repository exactly like the sync cache does, so
// repeated previews of the same candidate stay cheap; its only cost is the
// extra disk for the "-probe" sibling of TEMPLATE_SYNC_DIR.
func (s *TemplateSyncer) probeDir() string {
	return s.config.Dir + "-probe"
}

// resolveTemplateSnapshot fetches and checks out a candidate repo/ref in the
// probe cache and reads its catalog — the exact work a sync against the
// candidate would do — under the worktree lock shared with sync/preview probes
// (#343). The lock is taken with TryLock: a probe fails fast with
// errTemplateSyncBusy instead of holding the HTTP request for up to a whole
// sync budget behind a running refresh (PR #344 review #5).
//
// expectCommit is the commit a prior dry run resolved for this repo/ref (#343
// review #6): when the ref still resolves to it after the fetch, the snapshot
// is taken as already reviewed and the expensive catalog walk + custom-template
// shadow check are skipped — the queued sync re-checks the conflict inside its
// transaction. Empty expectCommit (or a moved ref) always walks.
//
// Before returning a walked snapshot, it is refused when any incoming id would
// shadow a custom template: ApplyUpstreamTemplates aborts the whole run on that
// conflict, so both the dry run and the save-time probe must surface it instead
// of letting a confirmed switch queue a sync that fails.
func (s *TemplateSyncer) resolveTemplateSnapshot(ctx context.Context, repo, ref, expectCommit string) (string, []store.Template, int, error) {
	if !s.worktree.TryLock() {
		return "", nil, 0, errTemplateSyncBusy
	}
	defer s.worktree.Unlock()
	dir := s.probeDir()
	r, err := openOrCloneTemplateRepo(ctx, dir, repo, s.log)
	if err != nil {
		return "", nil, 0, err
	}
	commit, err := checkoutTemplateRef(r, ref)
	if err != nil {
		return "", nil, 0, err
	}
	if expectCommit != "" && commit.String() == expectCommit {
		return commit.String(), nil, 0, nil
	}
	entries, skipped, err := readTemplateCatalog(dir, s.log)
	if err != nil {
		return "", nil, 0, err
	}
	// The syncer is always store-wired in production; nil-store constructions
	// exist only in tests, where there is no catalog to conflict with.
	if s.store != nil {
		conflict, err := s.store.FirstCustomTemplateConflict(ctx, templateIDs(entries))
		if err != nil {
			return "", nil, 0, err
		}
		if conflict != "" {
			return "", nil, 0, fmt.Errorf("upstream template id %q conflicts with a custom template", conflict)
		}
	}
	return commit.String(), entries, skipped, nil
}

// validateTemplateSource probes a candidate repo/ref at save time (#343):
// fetch, checkout, catalog walk, and the custom-template shadow check — the
// same refusals the queued sync would hit, run before the source is stored.
// No DB writes.
func (s *TemplateSyncer) validateTemplateSource(ctx context.Context, repo, ref string) error {
	_, _, _, err := s.resolveTemplateSnapshot(ctx, repo, ref, "")
	return err
}

// verifyTemplateSource is the save-time probe when the caller passes the
// commit a prior dry run resolved for this repo/ref (PR #344 review #6): the
// fetch + ref-resolve still run, but when the ref still resolves to that
// commit the catalog walk and shadow check are skipped and the whole probe
// costs one fetch. A moved ref simply walks the fresh snapshot (and runs the
// shadow check) in the same pass — the dry run's guarantees are preserved
// either way.
func (s *TemplateSyncer) verifyTemplateSource(ctx context.Context, repo, ref, expectCommit string) error {
	_, _, _, err := s.resolveTemplateSnapshot(ctx, repo, ref, expectCommit)
	return err
}

func templateIDs(entries []store.Template) []string {
	ids := make([]string, len(entries))
	for i, t := range entries {
		ids[i] = t.ID
	}
	return ids
}

func openOrCloneTemplateRepo(ctx context.Context, dir, remote string, log *slog.Logger) (*git.Repository, error) {
	repo, err := git.PlainOpen(dir)
	if err == nil {
		url, uerr := originTemplateURL(repo)
		// Identity is compared on the sanitized URL (PR #344 review #2): the
		// cache may hold the same repository with embedded credentials — only
		// scheme/host/path identify the repository. RemoteURL below points the
		// fetch at the requested URL, so rotated credentials apply without a
		// re-clone.
		if uerr == nil && SafeTemplateRepo(url) == SafeTemplateRepo(remote) {
			err = repo.FetchContext(ctx, &git.FetchOptions{RemoteName: "origin", RemoteURL: remote, Force: true, Tags: git.AllTags})
			if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
				return nil, fmt.Errorf("%w: fetch template repository: %v", errTemplateRepoUnreachable, err)
			}
			return repo, nil
		}
		// The cache points at a different repository (a stored-source switch):
		// a force fetch never deletes the previous repository's tags or
		// remote-tracking refs, so `latest` would still walk them and branch
		// lookup would still prefer stale origin refs. Replace the cache with a
		// fresh clone of the requested remote. Source probes never reach this
		// path — they run against the separate probe cache.
		if log != nil {
			log.Info("template clone cache points at a different repository; replacing it",
				"old_repo", SafeTemplateRepo(url), "repo", SafeTemplateRepo(remote))
		}
		if err := os.RemoveAll(dir); err != nil {
			return nil, fmt.Errorf("replace template clone cache: %w", err)
		}
	} else if !errors.Is(err, git.ErrRepositoryNotExists) {
		return nil, fmt.Errorf("open template repository: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return nil, fmt.Errorf("create template sync parent: %w", err)
	}
	repo, err = git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{URL: remote, Tags: git.AllTags})
	if err != nil {
		return nil, fmt.Errorf("%w: clone template repository: %v", errTemplateRepoUnreachable, err)
	}
	return repo, nil
}

// originTemplateURL returns the clone cache's origin URL (empty when no
// single-URL origin is configured, e.g. an interrupted clone). It is what lets
// the cache be replaced the moment it points somewhere else.
func originTemplateURL(repo *git.Repository) (string, error) {
	cfg, err := repo.Config()
	if err != nil {
		return "", fmt.Errorf("read template repository config: %w", err)
	}
	rem, ok := cfg.Remotes["origin"]
	if !ok || len(rem.URLs) != 1 {
		return "", nil
	}
	return rem.URLs[0], nil
}

func checkoutTemplateRef(repo *git.Repository, ref string) (plumbing.Hash, error) {
	hash, err := resolveRefHash(repo, ref)
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

// resolveRefHash maps the stored ref vocabulary to a commit: "latest" is the
// highest stable semver tag, anything else a git ref name or SHA.
func resolveRefHash(repo *git.Repository, ref string) (plumbing.Hash, error) {
	if ref == "latest" {
		return latestReleaseCommit(repo)
	}
	return resolveTemplateRef(repo, ref)
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
