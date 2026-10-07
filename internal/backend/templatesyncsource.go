package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Upstream template source switching (#343): the app_settings row is the
// source of record (seeded once from TEMPLATE_SYNC_REPO/TEMPLATE_SYNC_REF by
// the entrypoint). The admin API validates the candidate, resolves it against
// the fetched repository at save time, stores it, and queues an immediate
// sync. Repository URLs may embed credentials — they are stored verbatim but
// only ever returned through SafeTemplateRepo.

// errTemplateSyncUnavailable marks a Server built without the syncer/store
// wiring (tests, or upstream sync machinery absent).
var errTemplateSyncUnavailable = errors.New("template sync is not available")

// defaultTemplateSyncRef mirrors the TEMPLATE_SYNC_REF default.
const defaultTemplateSyncRef = "latest"

// allowedTemplateSyncRepoSchemes is the URL-scheme allowlist for the upstream
// template repository: HTTPS only. file:// and local paths are rejected so the
// syncer keeps fetching from a real remote and a compromised admin session
// cannot point it at backend-local files. git:// is plaintext and
// unauthenticated — template content runs against targets, so it must not be
// tamperable in transit (PR #344 review #10); ssh:// needs key material and a
// known_hosts file the container does not ship, so it could be stored but
// never fetched (PR #344 review #11) and stays out until both are supported.
var allowedTemplateSyncRepoSchemes = map[string]bool{
	"https": true,
}

// templateSyncSourceRequest is the PUT config / POST preview body. Repo is a
// pointer so omitted keeps the stored repository (write-only semantics, like
// node tokens and client keys) while an explicit empty string is the documented
// "upstream sync disabled" value. Ref is always required: the UI derives it
// from the Stable/Preview channel choice or the free-form field. PreviewCommit
// is optional: the commit a prior dry run resolved for this exact repo/ref,
// letting the save-time probe skip the expensive catalog walk (PR #344 review
// #6) — the queued sync re-checks custom-template conflicts transactionally.
type templateSyncSourceRequest struct {
	Repo          *string `json:"repo,omitempty"`
	Ref           string  `json:"ref"`
	PreviewCommit string  `json:"preview_commit,omitempty"`
}

// validateTemplateSyncRepo checks an upstream repository URL: absolute, an
// allowlisted scheme, and a host. The trimmed value (credentials included) is
// what gets stored.
func validateTemplateSyncRepo(raw string) (string, error) {
	repo := strings.TrimSpace(raw)
	u, err := url.Parse(repo)
	if err != nil {
		return "", fmt.Errorf("parse repository URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if !allowedTemplateSyncRepoSchemes[scheme] {
		if scheme == "" {
			return "", errors.New("repository must be an absolute URL with an https scheme")
		}
		return "", fmt.Errorf("repository scheme %q is not allowed: use https", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("repository URL must include a host")
	}
	return repo, nil
}

// validateTemplateSyncRef accepts the magic "latest" (highest stable semver
// tag), a full or abbreviated commit SHA, or a git ref name — validated with
// go-git's git-check-ref-format implementation rather than a hand-rolled
// parser. go-git's Validate requires a full name (at least two slash-separated
// components), so short names are checked where the resolver actually looks
// them up (refs/heads/<name>; branch/tag resolution then tracks upstream, see
// resolveTemplateRef).
func validateTemplateSyncRef(ref string) (string, error) {
	r := strings.TrimSpace(ref)
	if r == "" {
		return "", errors.New("ref is required")
	}
	if r == defaultTemplateSyncRef || isCommitSHA(r) {
		return r, nil
	}
	if strings.Contains(r, "/") {
		if err := plumbing.ReferenceName(r).Validate(); err != nil {
			return "", fmt.Errorf("invalid git ref %q: %w", r, err)
		}
		return r, nil
	}
	if err := plumbing.ReferenceName("refs/heads/" + r).Validate(); err != nil {
		return "", fmt.Errorf("invalid git ref %q: %w", r, err)
	}
	return r, nil
}

// isCommitSHA reports whether ref is a full or abbreviated commit SHA
// (4-40 hexadecimal characters) — a character-class check, not a parser.
func isCommitSHA(ref string) bool {
	if len(ref) < 4 || len(ref) > 40 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// effectiveTemplateSyncSource merges a request over the stored source. It
// writes the 400 itself when the candidate is invalid and returns ok=false.
// An explicit empty repository is valid (sync disabled) and skips probing.
func (s *Server) effectiveTemplateSyncSource(w http.ResponseWriter, stored store.TemplateSyncSource, req templateSyncSourceRequest) (store.TemplateSyncSource, bool) {
	next := stored
	if req.Repo != nil {
		repo := strings.TrimSpace(*req.Repo)
		if repo != "" {
			var err error
			if repo, err = validateTemplateSyncRepo(repo); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return store.TemplateSyncSource{}, false
			}
		}
		next.Repo = repo
	}
	ref, err := validateTemplateSyncRef(req.Ref)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return store.TemplateSyncSource{}, false
	}
	next.Ref = ref
	return next, true
}

// SeedTemplateSyncConfig seeds the DB-backed template-sync source from the
// environment exactly once (#343): still-NULL columns take the env-derived
// values (including their defaults); anything already stored wins. An env that
// differs from the stored values only logs a drift note — env is never
// re-applied over a stored value, and multiple replicas converge on the first
// stored value. Returns the effective source for the entrypoint's log line.
func SeedTemplateSyncConfig(ctx context.Context, st *store.Store, fromEnv store.TemplateSyncSource, log *slog.Logger) (store.TemplateSyncSource, error) {
	before, err := st.GetTemplateSyncSource(ctx)
	if err != nil {
		return store.TemplateSyncSource{}, fmt.Errorf("read template sync source before seeding: %w", err)
	}
	after, err := st.SeedTemplateSyncSource(ctx, fromEnv)
	if err != nil {
		return store.TemplateSyncSource{}, err
	}
	switch {
	case before.Repo == "" && before.Ref == "":
		log.Info("template sync source seeded from environment", "repo", SafeTemplateRepo(after.Repo), "ref", after.Ref)
	case after != fromEnv:
		log.Warn("template sync source differs from the environment; the stored configuration wins (change it in the UI under Templates → Sync)",
			"env_repo", SafeTemplateRepo(fromEnv.Repo), "env_ref", fromEnv.Ref,
			"repo", SafeTemplateRepo(after.Repo), "ref", after.Ref)
	default:
		log.Debug("template sync source matches the environment", "repo", SafeTemplateRepo(after.Repo), "ref", after.Ref)
	}
	return after, nil
}

// writeTemplateSourceError maps a probe failure to its response: 503 while the
// worktree lock is busy (fail fast instead of queueing behind a running sync,
// PR #344 review #5), a generic message for transport errors (the raw go-git
// error can name internal hosts — PR #344 review #7 — so the detail is logged
// server-side only), and the precise error otherwise (unknown ref, custom
// shadow conflict, empty snapshot).
func (s *Server) writeTemplateSourceError(w http.ResponseWriter, r *http.Request, err error, responsePrefix string) {
	switch {
	case errors.Is(err, errTemplateSyncBusy):
		http.Error(w, "a template sync or dry run is already in progress; try again in a few minutes", http.StatusServiceUnavailable)
	case errors.Is(err, errTemplateRepoUnreachable):
		if s.log != nil {
			s.log.Warn("template source probe failed", "path", r.URL.Path, "err", err)
		}
		http.Error(w, responsePrefix+": the candidate repository is unreachable, refused the connection, or rejected authentication; see the backend logs for details", http.StatusBadRequest)
	case errors.Is(err, context.DeadlineExceeded):
		http.Error(w, responsePrefix+": the probe timed out before the repository resolved; retry, or pick a ref reachable over a faster link", http.StatusBadRequest)
	default:
		http.Error(w, fmt.Sprintf("%s: %v", responsePrefix, err), http.StatusBadRequest)
	}
}

// handleUpdateTemplateSyncConfig stores a new upstream source and queues the
// immediate sync (#343). The save-time probe verifies the candidate in the
// probe cache — reusing the commit a prior dry run resolved when one was
// supplied (PR #344 review #6) — so an unreachable repository, an unknown ref,
// or a snapshot that would shadow a custom template is refused before anything
// is stored. The audit event carries the sanitized repository (old and new)
// and the old → new ref, never credentials.
func (s *Server) handleUpdateTemplateSyncConfig(w http.ResponseWriter, r *http.Request) {
	if s.templateSyncer == nil || s.store == nil {
		s.serviceUnavailable(w, "update template sync source", errTemplateSyncUnavailable)
		return
	}
	var req templateSyncSourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.PreviewCommit != "" && !isCommitSHA(req.PreviewCommit) {
		http.Error(w, "preview_commit must be a full or abbreviated commit SHA", http.StatusBadRequest)
		return
	}
	stored, err := s.store.GetTemplateSyncSource(r.Context())
	if err != nil {
		s.serverError(w, "read template sync source", err)
		return
	}
	next, ok := s.effectiveTemplateSyncSource(w, stored, req)
	if !ok {
		return
	}
	// No-op save (PR #344 review #14): storing the identical source would run
	// the whole probe → audit → sync-queue flow for nothing. The comparison is
	// on the raw values, so a credential rotation is a real change, not a no-op.
	if next == stored {
		status, ok := s.templateSyncStatusResponse(w, r)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, status)
		return
	}
	if strings.TrimSpace(next.Repo) != "" {
		ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
		err := s.templateSyncer.verifyTemplateSource(ctx, next.Repo, next.Ref, req.PreviewCommit)
		cancel()
		if err != nil {
			s.writeTemplateSourceError(w, r, err, "candidate template source failed to validate")
			return
		}
	}
	if _, err := s.store.UpdateTemplateSyncSource(r.Context(), next, identityFrom(r.Context()).Subject); err != nil {
		s.serverError(w, "update template sync source", err)
		return
	}
	addAuditFields(r,
		slog.String("old_ref", stored.Ref),
		slog.String("new_ref", next.Ref),
		slog.String("old_repo", SafeTemplateRepo(stored.Repo)),
		slog.String("repo", SafeTemplateRepo(next.Repo)),
	)
	// A sync already running finishes with its old config; the queued run reads
	// the new one (single-writer trigger). A disable needs no run.
	if strings.TrimSpace(next.Repo) != "" {
		s.templateSyncer.RequestSync()
	}
	status, ok := s.templateSyncStatusResponse(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// handlePreviewTemplateSyncSource runs the admin's dry run for a candidate
// source (#343): fetch + resolve + catalog diff in the probe cache, no DB
// writes. The route is audited as a mutation (PR #344 review #7): the preview
// sends the backend to an admin-supplied host, so the attempt — including
// rejected ones — leaves a structured trace. It is a cookie-authenticated POST
// that kicks off network work, so the mutation origin guard also applies.
func (s *Server) handlePreviewTemplateSyncSource(w http.ResponseWriter, r *http.Request) {
	if !s.mutationOriginAllowed(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	if s.templateSyncer == nil || s.store == nil {
		s.serviceUnavailable(w, "preview template sync source", errTemplateSyncUnavailable)
		return
	}
	var req templateSyncSourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	stored, err := s.store.GetTemplateSyncSource(r.Context())
	if err != nil {
		s.serverError(w, "read template sync source", err)
		return
	}
	candidate, ok := s.effectiveTemplateSyncSource(w, stored, req)
	if !ok {
		return
	}
	if strings.TrimSpace(candidate.Repo) == "" {
		http.Error(w, "repository is required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()
	preview, err := s.templateSyncer.PreviewSource(ctx, candidate.Repo, candidate.Ref)
	if err != nil {
		// An unreachable repo or unknown ref is the input's fault: the caller
		// gets the probe error instead of a stored-but-broken source.
		s.writeTemplateSourceError(w, r, err, "template source preview failed")
		return
	}
	addAuditFields(r,
		slog.String("repo", preview.Repo),
		slog.String("ref", preview.Ref),
		slog.String("commit", preview.Commit),
	)
	writeJSON(w, http.StatusOK, preview)
}
