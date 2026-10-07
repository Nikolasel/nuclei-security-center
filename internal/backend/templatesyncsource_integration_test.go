package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// buildTemplateRepoFixture creates a local repository standing in for an
// upstream template catalog: the tagged stable release carries alpha/beta/shared
// (or, with stableIDs, only those templates — byte-identical bodies for shared
// ids, so a narrow fixture tombstones the rest when stored), the moving main
// branch carries alpha(v2)/gamma/shared. Returned as a plain filesystem path —
// go-git's local transport, exactly what the clone cache fetches; the HTTP
// allowlist tests cover URL validation separately.
func buildTemplateRepoFixture(t *testing.T, stableIDs ...string) string {
	t.Helper()
	if len(stableIDs) == 0 {
		stableIDs = []string{"alpha", "beta", "shared"}
	}
	// Fixed per-id bodies keep a template's content hash equal across
	// fixtures that both carry it.
	stableDesc := map[string]string{"alpha": "stable", "beta": "stable only", "shared": "both refs"}
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init fixture repository: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("open fixture worktree: %v", err)
	}
	sig := &object.Signature{Name: "fixture", Email: "fixture@example.test", When: time.Now()}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write fixture template: %v", err)
		}
	}
	templateYAML := func(id, desc string) string {
		name := strings.ToUpper(id[:1]) + id[1:]
		return fmt.Sprintf("id: %s\ninfo:\n  name: %s\n  author: fixture\n  severity: medium\n  description: %s\n", id, name, desc)
	}
	commit := func(msg string) {
		t.Helper()
		if err := wt.AddWithOptions(&git.AddOptions{All: true}); err != nil {
			t.Fatalf("stage fixture templates: %v", err)
		}
		if _, err := wt.Commit(msg, &git.CommitOptions{Author: sig}); err != nil {
			t.Fatalf("commit fixture templates: %v", err)
		}
	}

	for _, id := range stableIDs {
		write(id+".yaml", templateYAML(id, stableDesc[id]))
	}
	commit("stable catalog")

	head, err := repo.Head()
	if err != nil {
		t.Fatalf("read fixture HEAD: %v", err)
	}
	if _, err := repo.CreateTag("v1.0.0", head.Hash(), &git.CreateTagOptions{
		Tagger:  sig,
		Message: "stable release",
	}); err != nil {
		t.Fatalf("tag fixture release: %v", err)
	}

	// main drops the stable-only templates, rewrites alpha, adds gamma.
	for _, id := range stableIDs {
		if id == "alpha" || id == "shared" {
			continue
		}
		if err := os.Remove(filepath.Join(dir, id+".yaml")); err != nil {
			t.Fatalf("remove fixture %s: %v", id, err)
		}
	}
	write("alpha.yaml", templateYAML("alpha", "preview"))
	write("gamma.yaml", templateYAML("gamma", "preview only"))
	commit("preview catalog")
	if err := wt.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName("main"),
		Create: true,
		Force:  true,
	}); err != nil {
		t.Fatalf("create fixture main branch: %v", err)
	}
	return dir
}

func activeUpstreamIDs(t *testing.T, st *store.Store, ctx context.Context) []string {
	t.Helper()
	items, _, err := st.ListTemplates(ctx, store.TemplateFilter{Source: "upstream"}, 500, 0)
	if err != nil {
		t.Fatalf("list upstream templates: %v", err)
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

// TestTemplateSyncSwitchAndReconcilePostgres covers the acceptance flow (#343):
// stable → preview → stable → preview, each step reconciling in place — set
// memberships survive, removed templates are tombstoned, returning templates
// are restored — plus the dry-run impact counts and the runtime-disabled state.
func TestTemplateSyncSwitchAndReconcilePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	fixture := buildTemplateRepoFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	syncer, err := NewTemplateSyncer(st, TemplateSyncerConfig{Interval: time.Hour, Dir: filepath.Join(t.TempDir(), "clone-cache")}, testLogger())
	if err != nil {
		t.Fatalf("wire template syncer: %v", err)
	}
	if _, err := st.SeedTemplateSyncSource(ctx, store.TemplateSyncSource{Repo: fixture, Ref: "latest"}); err != nil {
		t.Fatalf("seed template sync source: %v", err)
	}

	switchTo := func(repo, ref string) {
		t.Helper()
		if _, err := st.UpdateTemplateSyncSource(ctx, store.TemplateSyncSource{Repo: repo, Ref: ref}, ""); err != nil {
			t.Fatalf("switch template source to %s@%s: %v", repo, ref, err)
		}
		syncer.run(ctx, repo, ref)
		runs, _, err := st.ListTemplateSyncRuns(ctx, 1, 0)
		if err != nil {
			t.Fatalf("read last sync run: %v", err)
		}
		if len(runs) == 0 || runs[0].Status != "success" {
			t.Fatalf("sync run for %s@%s = %+v, want success", repo, ref, runs)
		}
	}

	// 1. Stable baseline: alpha, beta, shared active.
	switchTo(fixture, "latest")
	if got := activeUpstreamIDs(t, st, ctx); len(got) != 3 {
		t.Fatalf("stable catalog = %v, want alpha/beta/shared", got)
	}
	set, err := st.CreateTemplateSet(ctx, store.TemplateSet{Name: "reconcile-set", Mode: store.TemplateSetModeExact, CreatedBy: "tester"})
	if err != nil {
		t.Fatalf("create template set: %v", err)
	}
	if _, err := st.ReplaceTemplateSetMembers(ctx, set.ID, []string{"alpha", "beta"}, "tester"); err != nil {
		t.Fatalf("fill template set: %v", err)
	}

	// 2. Dry run of the preview source: beta removed, alpha changed, gamma
	// added; the exact set is named with its member counts. No DB writes.
	preview, err := syncer.PreviewSource(ctx, fixture, "main")
	if err != nil {
		t.Fatalf("preview main: %v", err)
	}
	if preview.Added != 1 || preview.Changed != 1 || preview.Restored != 0 || preview.Removed != 1 {
		t.Fatalf("preview counts = added %d changed %d restored %d removed %d, want 1/1/0/1",
			preview.Added, preview.Changed, preview.Restored, preview.Removed)
	}
	if len(preview.AffectedSets) != 1 || preview.AffectedSets[0].ID != set.ID ||
		preview.AffectedSets[0].MemberCount != 2 || preview.AffectedSets[0].LosingCount != 1 {
		t.Fatalf("preview affected sets = %+v, want %s with member 2 losing 1", preview.AffectedSets, set.ID)
	}
	if len(preview.RegainedSets) != 0 || len(preview.AffectedPolicies) != 0 || len(preview.AffectedSchedules) != 0 {
		t.Fatalf("preview on the untouched catalog lists regained sets or users: %+v", preview)
	}
	if got := activeUpstreamIDs(t, st, ctx); len(got) != 3 {
		t.Fatalf("preview wrote to the catalog: %v", got)
	}

	// 3. Switch to main: beta tombstoned (not deleted), gamma added, set
	// membership rows survive pointing at the tombstoned id. The run row
	// records the sanitized source it read, so history can show the switch.
	switchTo(fixture, "main")
	if got := activeUpstreamIDs(t, st, ctx); len(got) != 3 {
		t.Fatalf("main catalog = %v, want alpha/gamma/shared", got)
	}
	if last, _, err := st.ListTemplateSyncRuns(ctx, 1, 0); err != nil ||
		last[0].SourceRepo != SafeTemplateRepo(fixture) || last[0].SourceRef != "main" {
		t.Fatalf("last run source = %+v, want sanitized fixture/main", last)
	}
	beta, err := st.GetTemplate(ctx, "beta")
	if err != nil {
		t.Fatalf("read tombstoned beta: %v", err)
	}
	if beta.Availability != "unavailable" || beta.Path != "tombstone:beta" {
		t.Fatalf("beta after switch = availability %q path %q, want unavailable + tombstone path", beta.Availability, beta.Path)
	}
	afterSwitch, err := st.GetTemplateSet(ctx, set.ID)
	if err != nil {
		t.Fatalf("read template set after switch: %v", err)
	}
	if afterSwitch.MemberCount != 2 {
		t.Fatalf("set member count after switch = %d, want 2 (membership survives)", afterSwitch.MemberCount)
	}

	// 3b. Dry run of the stable source from main: gamma would be removed, beta
	// would be restored. The set no longer holds any would-be-removed id, so
	// the JSON carries a non-null empty affected_sets (the nil-slice regression
	// from the PR #344 review) while the set appears in regained_sets — after
	// the switch it becomes scannable again.
	previewLatest, err := syncer.PreviewSource(ctx, fixture, "latest")
	if err != nil {
		t.Fatalf("preview latest from main: %v", err)
	}
	if previewLatest.Removed != 1 || previewLatest.Restored != 1 || previewLatest.Added != 0 || previewLatest.Changed != 1 {
		t.Fatalf("preview latest counts = %+v, want removed 1 restored 1 added 0 changed 1 (alpha's content differs)", previewLatest)
	}
	if len(previewLatest.AffectedSets) != 0 {
		t.Fatalf("preview latest affected sets = %+v, want none (no exact set holds gamma)", previewLatest.AffectedSets)
	}
	if blob, jerr := json.Marshal(previewLatest); jerr != nil || !bytes.Contains(blob, []byte(`"affected_sets":[]`)) {
		t.Fatalf("preview latest JSON = %s (%v), want a non-null empty affected_sets", blob, jerr)
	}
	if len(previewLatest.RegainedSets) != 1 || previewLatest.RegainedSets[0].ID != set.ID ||
		previewLatest.RegainedSets[0].MemberCount != 2 || previewLatest.RegainedSets[0].RegainingCount != 1 {
		t.Fatalf("preview latest regained sets = %+v, want %s regaining 1 of 2", previewLatest.RegainedSets, set.ID)
	}

	// 4. Back to stable: beta is restored by the upsert, gamma tombstoned.
	switchTo(fixture, "latest")
	beta, err = st.GetTemplate(ctx, "beta")
	if err != nil {
		t.Fatalf("read restored beta: %v", err)
	}
	if beta.Availability != "active" || beta.Path != "beta.yaml" {
		t.Fatalf("beta after return = availability %q path %q, want active + beta.yaml", beta.Availability, beta.Path)
	}
	gamma, err := st.GetTemplate(ctx, "gamma")
	if err != nil {
		t.Fatalf("read tombstoned gamma: %v", err)
	}
	if gamma.Availability != "unavailable" {
		t.Fatalf("gamma after return = %q, want unavailable", gamma.Availability)
	}

	// 4b. A set is claimed regained only when the candidate restores ALL of
	// its currently-unavailable members (PR #344 review): a narrower source
	// tombstones beta and gamma, a dry run back to the full fixture restores
	// only beta, so the {beta,gamma} set stays refused at dispatch and must
	// not be listed as scannable again — while the {alpha,beta} set is.
	narrow := buildTemplateRepoFixture(t, "alpha", "shared")
	switchTo(narrow, "latest")
	if got := activeUpstreamIDs(t, st, ctx); len(got) != 2 {
		t.Fatalf("narrow catalog = %v, want alpha/shared", got)
	}
	partialSet, err := st.CreateTemplateSet(ctx, store.TemplateSet{Name: "partial-regain-set", Mode: store.TemplateSetModeExact, CreatedBy: "tester"})
	if err != nil {
		t.Fatalf("create partial-regain template set: %v", err)
	}
	if _, err := st.ReplaceTemplateSetMembers(ctx, partialSet.ID, []string{"beta", "gamma"}, "tester"); err != nil {
		t.Fatalf("fill partial-regain template set: %v", err)
	}
	previewPartial, err := syncer.PreviewSource(ctx, fixture, "latest")
	if err != nil {
		t.Fatalf("preview latest from the narrow source: %v", err)
	}
	if previewPartial.Restored != 1 || previewPartial.Removed != 0 {
		t.Fatalf("preview from the narrow source = %+v, want restored 1 (beta) removed 0", previewPartial)
	}
	if len(previewPartial.RegainedSets) != 1 || previewPartial.RegainedSets[0].ID != set.ID {
		t.Fatalf("preview from the narrow source regained sets = %+v, want only %s (the partial set stays refused)",
			previewPartial.RegainedSets, set.ID)
	}
	switchTo(fixture, "latest")
	if got := activeUpstreamIDs(t, st, ctx); len(got) != 3 {
		t.Fatalf("catalog after leaving the narrow source = %v, want alpha/beta/shared", got)
	}

	// 5. Preview → stable → preview restore: gamma comes back.
	switchTo(fixture, "main")
	if got := activeUpstreamIDs(t, st, ctx); len(got) != 3 {
		t.Fatalf("re-switched main catalog = %v, want alpha/gamma/shared", got)
	}
	gamma, err = st.GetTemplate(ctx, "gamma")
	if err != nil {
		t.Fatalf("read restored gamma: %v", err)
	}
	if gamma.Availability != "active" || gamma.Path != "gamma.yaml" {
		t.Fatalf("gamma after re-switch = availability %q path %q, want active + gamma.yaml", gamma.Availability, gamma.Path)
	}

	// 6. Resolve-at-save: both refs resolve in the fetched clone, and no custom
	// template shadows the snapshot's ids (the refusal itself is covered by
	// TestTemplateSyncSourceCustomCollisionRefusedPostgres, which needs a store
	// without upstream rows).
	if err := syncer.validateTemplateSource(ctx, fixture, "latest"); err != nil {
		t.Fatalf("validate latest at save time: %v", err)
	}
	if err := syncer.validateTemplateSource(ctx, fixture, "main"); err != nil {
		t.Fatalf("validate main at save time: %v", err)
	}
	if err := syncer.validateTemplateSource(ctx, fixture, "no-such-ref"); err == nil {
		t.Fatal("validate of an unknown ref succeeded, want error")
	}
	if id, err := st.FirstCustomTemplateConflict(ctx, []string{"alpha", "beta", "shared"}); err != nil || id != "" {
		t.Fatalf("FirstCustomTemplateConflict on the snapshot's ids = %q, %v, want no conflict", id, err)
	}

	// 7. An explicitly empty repository disables upstream sync at runtime: the
	// syncer runs but records no run and changes nothing.
	runsBefore, _, err := st.ListTemplateSyncRuns(ctx, 1, 0)
	if err != nil {
		t.Fatalf("count sync runs before disable: %v", err)
	}
	if _, err := st.UpdateTemplateSyncSource(ctx, store.TemplateSyncSource{Repo: "", Ref: "latest"}, ""); err != nil {
		t.Fatalf("disable upstream sync: %v", err)
	}
	syncer.sync(ctx)
	runsAfter, _, err := st.ListTemplateSyncRuns(ctx, 1, 0)
	if err != nil {
		t.Fatalf("count sync runs after disable: %v", err)
	}
	if len(runsAfter) != len(runsBefore) {
		t.Fatalf("disabled sync recorded a run (%d → %d), want none", len(runsBefore), len(runsAfter))
	}
	if got := activeUpstreamIDs(t, st, ctx); len(got) != 3 {
		t.Fatalf("disabled sync changed the catalog: %v", got)
	}
}

// TestTemplateSyncSourceCustomCollisionRefusedPostgres covers the shadowing
// refusal (#343): ApplyUpstreamTemplates aborts a whole run when an incoming id
// matches a custom template, so both the dry run and the save-time probe must
// refuse the candidate up front instead of letting a confirmed switch queue a
// sync that fails. A fresh store keeps every catalog id free for the custom row.
func TestTemplateSyncSourceCustomCollisionRefusedPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	fixture := buildTemplateRepoFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	syncer, err := NewTemplateSyncer(st, TemplateSyncerConfig{Interval: time.Hour, Dir: filepath.Join(t.TempDir(), "clone-cache")}, testLogger())
	if err != nil {
		t.Fatalf("wire template syncer: %v", err)
	}
	if _, err := st.CreateCustomTemplate(ctx, store.Template{
		ID: "alpha", Path: "custom/alpha.yaml", YAML: "id: alpha\n",
		ContentSHA256: "sha-alpha", Name: "alpha", Severity: "low",
	}); err != nil {
		t.Fatalf("create shadowing custom template: %v", err)
	}
	if id, err := st.FirstCustomTemplateConflict(ctx, []string{"alpha", "beta"}); err != nil || id != "alpha" {
		t.Fatalf("FirstCustomTemplateConflict = %q, %v, want alpha", id, err)
	}
	conflict := "conflicts with a custom template"
	if err := syncer.validateTemplateSource(ctx, fixture, "latest"); err == nil || !strings.Contains(err.Error(), conflict) {
		t.Fatalf("validate with a shadowing custom template = %v, want %q", err, conflict)
	}
	preview, err := syncer.PreviewSource(ctx, fixture, "latest")
	if err == nil || !strings.Contains(err.Error(), conflict) {
		t.Fatalf("preview with a shadowing custom template = %v, want the same refusal surfaced", err)
	}
	if preview.Added != 0 || preview.Changed != 0 || preview.Removed != 0 {
		t.Fatalf("preview on the refused candidate returned counts %+v, want zeroed", preview)
	}
	if err := st.DeleteCustomTemplate(ctx, "alpha"); err != nil {
		t.Fatalf("delete shadowing custom template: %v", err)
	}
	if err := syncer.validateTemplateSource(ctx, fixture, "latest"); err != nil {
		t.Fatalf("validate after removing the custom template: %v", err)
	}
}

// TestTemplateSyncConfigRBACAndAuditPostgres exercises the route wrappers: a
// viewer is refused with an audited access_denied, an admin disable stores and
// audits old → new ref with only the sanitized repository, and an unreachable
// candidate is refused without changing the stored source.
func TestTemplateSyncConfigRBACAndAuditPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	auth := &Authenticator{
		store: st,
		log:   slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		cfg:   AuthConfig{CookieName: "nsc_session", SecureCookie: false, SessionTTL: DefaultSessionTTL, PublicOrigin: "http://localhost:8080"},
	}
	syncer, err := NewTemplateSyncer(st, TemplateSyncerConfig{Interval: time.Hour, Dir: filepath.Join(t.TempDir(), "clone-cache")}, testLogger())
	if err != nil {
		t.Fatalf("wire template syncer: %v", err)
	}
	srv := NewServer(st, nil, auth, nil, http.NotFoundHandler(), log, "")
	srv.SetTemplateSyncer(syncer)
	h := srv.Handler()

	session := func(roles ...string) string {
		t.Helper()
		cookie := "session-" + types.NewID()
		if err := st.CreateSession(ctx, store.Session{
			ID:        cookie,
			Identity:  store.Identity{Subject: "user-" + types.NewID(), Roles: roles},
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("create %v session: %v", roles, err)
		}
		return cookie
	}
	withCookie := func(req *http.Request, cookie string) *http.Request {
		req.AddCookie(&http.Cookie{Name: "nsc_session", Value: cookie})
		// Cookie-authenticated POST/PUT requires a same-origin signal, and a
		// JSON body requires the matching content type.
		req.Header.Set("Origin", "http://localhost:8080")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		return req
	}

	viewer := session(RoleViewer)
	operator := session(RoleOperator)
	admin := session(RoleAdmin)

	// Viewer: 403 with an audited access_denied for both endpoints.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPut, "/api/templates/sync/config", strings.NewReader(`{"ref":"main"}`)), viewer))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT status = %d, want 403 body %q", rr.Code, rr.Body.String())
	}
	event := lastAudit(t, &logs)
	if event["event_id"] != eventAccessDenied || event["status"] != float64(http.StatusForbidden) {
		t.Fatalf("viewer PUT audit = %+v, want access_denied 403", event)
	}
	if event["action"] != "template_sync.config_update" {
		t.Fatalf("viewer PUT audit action = %v, want template_sync.config_update", event["action"])
	}

	logs.Reset()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPost, "/api/templates/sync/preview", strings.NewReader(`{"ref":"main"}`)), viewer))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer preview status = %d, want 403", rr.Code)
	}

	// Operator: same refusal on the config route (admin only).
	logs.Reset()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPut, "/api/templates/sync/config", strings.NewReader(`{"ref":"main"}`)), operator))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("operator PUT status = %d, want 403", rr.Code)
	}
	if event := lastAudit(t, &logs); event["event_id"] != eventAccessDenied {
		t.Fatalf("operator PUT audit event_id = %v, want access_denied", event["event_id"])
	}

	// Admin, validation failures: invalid ref and a disallowed scheme are
	// refused before anything is stored.
	for name, body := range map[string]string{
		"invalid ref": `{"ref":"bad ref"}`,
		"file repo":   `{"repo":"file:///etc/templates","ref":"latest"}`,
		"missing ref": `{"repo":"https://github.com/projectdiscovery/nuclei-templates.git"}`,
		"local path":  `{"repo":"../nuclei-templates","ref":"latest"}`,
		"plain http":  `{"repo":"http://github.com/projectdiscovery/nuclei-templates.git","ref":"latest"}`,
		"unreachable": `{"repo":"https://127.0.0.1:1/nope.git","ref":"main"}`,
		"unknown ref": `{"repo":"https://127.0.0.1:1/nope.git","ref":"no-such-ref"}`,
	} {
		logs.Reset()
		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPut, "/api/templates/sync/config", strings.NewReader(body)), admin))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: PUT status = %d, want 400 body %q", name, rr.Code, rr.Body.String())
		}
		src, err := st.GetTemplateSyncSource(ctx)
		if err != nil {
			t.Fatalf("%s: read stored source: %v", name, err)
		}
		if src.Repo != "" || src.Ref != "" {
			t.Fatalf("%s: stored source changed to %+v, want untouched", name, src)
		}
	}

	// Admin success: an explicit empty repository (disable) needs no probe, so
	// the full store + audit path runs hermetically. Audit carries old → new
	// ref and the sanitized repo, never credentials.
	if _, err := st.SeedTemplateSyncSource(ctx, store.TemplateSyncSource{
		Repo: "https://user:secret@example.test/templates.git", Ref: "v9.9.9",
	}); err != nil {
		t.Fatalf("seed credential-bearing source: %v", err)
	}
	logs.Reset()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPut, "/api/templates/sync/config", strings.NewReader(`{"repo":"","ref":"latest"}`)), admin))
	if rr.Code != http.StatusOK {
		t.Fatalf("admin disable status = %d, want 200 body %q", rr.Code, rr.Body.String())
	}
	var status struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil || status.Enabled {
		t.Fatalf("admin disable response = %s (%v), want enabled=false", rr.Body.String(), err)
	}
	event = lastAudit(t, &logs)
	if event["event_id"] != eventConfigChanged || event["action"] != "template_sync.config_update" {
		t.Fatalf("admin disable audit = %+v, want config_changed/template_sync.config_update", event)
	}
	if event["old_ref"] != "v9.9.9" || event["new_ref"] != "latest" {
		t.Fatalf("admin disable audit refs = %v → %v, want v9.9.9 → latest", event["old_ref"], event["new_ref"])
	}
	if event["old_repo"] != "https://example.test/templates.git" {
		t.Fatalf("admin disable audit old_repo = %v, want the sanitized previous repository (PR #344 review #12)", event["old_repo"])
	}
	if event["repo"] != "" {
		t.Fatalf("admin disable audit repo = %v, want sanitized/empty", event["repo"])
	}
	if strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), "user:") {
		t.Fatalf("audit log leaked credentials: %s", logs.String())
	}

	// "Sync now" refuses a disabled source instead of queueing a silent no-op.
	logs.Reset()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPost, "/api/templates/sync", nil), admin))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("sync-now while disabled status = %d, want 503", rr.Code)
	}

	// Omitted repo keeps the stored value (write-only semantics). Re-store a
	// locally resolvable repository first (the disable case above cleared the
	// stored URL), so the save-time probe succeeds hermetically and only the
	// ref changes.
	fixture := buildTemplateRepoFixture(t)
	if _, err := st.UpdateTemplateSyncSource(ctx, store.TemplateSyncSource{
		Repo: fixture, Ref: "latest",
	}, ""); err != nil {
		t.Fatalf("re-store resolvable source: %v", err)
	}

	// A candidate that would shadow a custom template is refused with 400 and
	// the stored source stays untouched — the queued sync would otherwise fail
	// after the switch was already confirmed.
	if _, err := st.CreateCustomTemplate(ctx, store.Template{
		ID: "alpha", Path: "custom/alpha.yaml", YAML: "id: alpha\n",
		ContentSHA256: "sha-alpha", Name: "alpha", Severity: "low",
	}); err != nil {
		t.Fatalf("create shadowing custom template: %v", err)
	}
	logs.Reset()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPut, "/api/templates/sync/config", strings.NewReader(`{"ref":"main"}`)), admin))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "conflicts with a custom template") {
		t.Fatalf("shadowing PUT = %d %q, want 400 naming the custom-template conflict", rr.Code, rr.Body.String())
	}
	if src, err := st.GetTemplateSyncSource(ctx); err != nil || src.Repo != fixture || src.Ref != "latest" {
		t.Fatalf("stored source after refused PUT = %+v (%v), want fixture@latest untouched", src, err)
	}
	if err := st.DeleteCustomTemplate(ctx, "alpha"); err != nil {
		t.Fatalf("delete shadowing custom template: %v", err)
	}
	logs.Reset()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPut, "/api/templates/sync/config", strings.NewReader(`{"ref":"main"}`)), admin))
	if rr.Code != http.StatusOK {
		t.Fatalf("admin keep-repo status = %d, want 200 body %q", rr.Code, rr.Body.String())
	}
	src, err := st.GetTemplateSyncSource(ctx)
	if err != nil {
		t.Fatalf("read source after keep: %v", err)
	}
	if src.Repo != fixture || src.Ref != "main" {
		t.Fatalf("source after keep = %+v, want stored repo with ref main", src)
	}
	if event := lastAudit(t, &logs); event["repo"] != SafeTemplateRepo(fixture) {
		t.Fatalf("audit repo = %v, want the sanitized stored repository", event["repo"])
	}

	// A no-op save (identical source) short-circuits: 200, no probe, no queued
	// sync (PR #344 review #14). The mutation wrapper still emits its one audit
	// event — every mutating API call is audited — but with no old/new delta
	// because nothing changed. A sync queued by the previous PUT may still be
	// logging into the shared buffer, so assert on the audit events, not the
	// whole buffer.
	logs.Reset()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPut, "/api/templates/sync/config", strings.NewReader(`{"ref":"main"}`)), admin))
	if rr.Code != http.StatusOK {
		t.Fatalf("no-op save status = %d, want 200 body %q", rr.Code, rr.Body.String())
	}
	noopUpdates := 0
	for _, line := range bytes.Split(bytes.TrimRight(logs.Bytes(), "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev map[string]any
		if json.Unmarshal(line, &ev) != nil || ev["event"] != "audit" || ev["action"] != "template_sync.config_update" {
			continue
		}
		noopUpdates++
		if ev["new_ref"] != nil {
			t.Fatalf("no-op audit carried new_ref %v, want no old/new delta", ev["new_ref"])
		}
	}
	if noopUpdates != 1 {
		t.Fatalf("no-op save emitted %d template_sync.config_update audit events, want 1", noopUpdates)
	}

	// The preview dry run is audited (PR #344 review #7) and a transport
	// failure surfaces as a generic 400 — the raw dial error names internal
	// hosts and stays in the server log only.
	logs.Reset()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodPost, "/api/templates/sync/preview", strings.NewReader(`{"repo":"https://127.0.0.1:1/nope.git","ref":"main"}`)), admin))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unreachable preview status = %d, want 400 body %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unreachable, refused the connection") || strings.Contains(rr.Body.String(), "dial tcp") {
		t.Fatalf("unreachable preview body = %q, want the generic message without the transport error", rr.Body.String())
	}
	if event := lastAudit(t, &logs); event["action"] != "template_sync.preview" || event["event_id"] != eventConfigChanged {
		t.Fatalf("preview audit = %+v, want config_changed/template_sync.preview", event)
	}

	// GET status reports the DB-backed source with the channel label. Restore
	// the credential-bearing URL at store level so the response also proves
	// sanitization; the environment view marks the seed-only variables and
	// shows the DB value.
	if _, err := st.UpdateTemplateSyncSource(ctx, store.TemplateSyncSource{
		Repo: "https://user:secret@example.test/templates.git", Ref: "main",
	}, ""); err != nil {
		t.Fatalf("re-store credential-bearing source: %v", err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodGet, "/api/templates/sync", nil), admin))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET sync status = %d, want 200", rr.Code)
	}
	var syncStatus struct {
		Enabled   bool   `json:"enabled"`
		RefSource string `json:"ref_source"`
		Repo      string `json:"repo"`
		Ref       string `json:"ref"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &syncStatus); err != nil {
		t.Fatalf("decode sync status: %v", err)
	}
	if !syncStatus.Enabled || syncStatus.RefSource != templateSyncChannelCustom || syncStatus.Ref != "main" {
		t.Fatalf("sync status = %+v, want enabled custom/main (main is only preview on the default repository, PR #344 review #15)", syncStatus)
	}
	if syncStatus.Repo != "https://example.test/templates.git" {
		t.Fatalf("sync status repo = %q, want sanitized", syncStatus.Repo)
	}
	if strings.Contains(rr.Body.String(), "secret") {
		t.Fatalf("sync status leaked credentials: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, withCookie(httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil), admin))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET environment status = %d, want 200", rr.Code)
	}
	var env struct {
		Variables []struct {
			Name      string  `json:"name"`
			SeedOnly  bool    `json:"seed_only"`
			Effective *string `json:"effective"`
		} `json:"variables"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode environment: %v", err)
	}
	byName := map[string]struct {
		seedOnly  bool
		effective string
	}{}
	for _, v := range env.Variables {
		effective := ""
		if v.Effective != nil {
			effective = *v.Effective
		}
		byName[v.Name] = struct {
			seedOnly  bool
			effective string
		}{v.SeedOnly, effective}
	}
	if row := byName["TEMPLATE_SYNC_REPO"]; !row.seedOnly || row.effective != "https://example.test/templates.git" {
		t.Fatalf("TEMPLATE_SYNC_REPO row = %+v, want seed-only with sanitized DB value", row)
	}
	if row := byName["TEMPLATE_SYNC_REF"]; !row.seedOnly || row.effective != "main" {
		t.Fatalf("TEMPLATE_SYNC_REF row = %+v, want seed-only with DB value main", row)
	}
	if row := byName["TEMPLATE_SYNC_INTERVAL"]; row.seedOnly {
		t.Fatalf("TEMPLATE_SYNC_INTERVAL must stay env-only, got %+v", row)
	}
}
