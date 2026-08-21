package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
	"github.com/Nikolasel/nuclei-security-center/web"
)

// Server is the backend's HTTP API. Mutating and read endpoints are guarded by
// OIDC/BFF auth (§6); when auth is nil (OIDC unconfigured) the guards fall back
// to a dev identity with all roles, so local smoke tests still work.
type Server struct {
	store                  *store.Store
	orch                   *Orchestrator
	auth                   *Authenticator
	archive                ObjectStore          // nil when object storage is not configured
	searcher               FindingsSearcher     // reads the findings list; defaults to Postgres
	templateSyncer         *TemplateSyncer      // nil when upstream catalog sync is disabled
	distributor            *TemplateDistributor // nil when template sync is disabled (#85)
	templateValidator      func(context.Context, []byte) (types.TemplateValidationResult, error)
	templateBatchValidator func(context.Context, []store.TemplateImportWrite) (types.TemplateBatchValidationResult, error)
	spa                    http.Handler
	log                    *slog.Logger
	exportSlots            chan struct{}
	exportSlotsOnce        sync.Once
	scanBundleImportSlots  chan struct{}
	scanBundleImportOnce   sync.Once
	exportSpoolDir         string
	exportStore            findingsExportStore
}

// SetTemplateSyncer wires the upstream catalog status/trigger API.
func (s *Server) SetTemplateSyncer(syncer *TemplateSyncer) { s.templateSyncer = syncer }

// SetTemplateDistributor wires both the admin "sync now" action and the
// orchestrator's pre-dispatch top-up (#85).
func (s *Server) SetTemplateDistributor(d *TemplateDistributor) {
	s.distributor = d
	s.orch.SetTemplateDistributor(d)
}

// NewServer builds the backend HTTP server. auth may be nil to disable auth; spa
// is the handler for the embedded frontend (served for all non-/api routes). The
// findings searcher defaults to Postgres; SetFindingsSearcher swaps it. The
// entrypoint validates exportSpoolDir before passing it here.
func NewServer(st *store.Store, orch *Orchestrator, auth *Authenticator, archive ObjectStore, spa http.Handler, log *slog.Logger, exportSpoolDir string) *Server {
	if exportSpoolDir == "" {
		exportSpoolDir = os.TempDir()
	}
	s := &Server{
		store:                 st,
		orch:                  orch,
		auth:                  auth,
		archive:               archive,
		searcher:              pgSearcher{store: st},
		spa:                   spa,
		log:                   log,
		exportSlots:           make(chan struct{}, maxConcurrentFindingExports),
		scanBundleImportSlots: make(chan struct{}, maxConcurrentScanBundleImports),
		exportSpoolDir:        exportSpoolDir,
		exportStore:           st,
	}
	s.templateValidator = s.validateCustomTemplate
	s.templateBatchValidator = s.validateCustomTemplateBatch
	return s
}

// SetFindingsSearcher swaps the backend for GET /api/findings (default: Postgres).
func (s *Server) SetFindingsSearcher(searcher FindingsSearcher) { s.searcher = searcher }

// defaultOptions are the sane rate/concurrency/timeout defaults applied when a
// caller doesn't specify their own.
func defaultOptions() types.ScanOptions {
	return types.ScanOptions{RateLimit: 150, Concurrency: 25, TimeoutSec: 600}
}

// securityHeaders wraps every response (SPA shell, assets, JSON API, healthz)
// with baseline hardening headers. It runs first so even authz denials and
// 404s are covered. The policy and header names are defined in web
// (SecurityHeadersCSP / SetSecurityHeaders) so the SPA file handler and the
// API share a single source of truth and cannot drift. Strict-Transport-
// Security is deliberately not set here — HSTS is the TLS-terminating
// ingress's responsibility (the app doesn't know if it's behind HTTPS), and
// the comment on the middleware makes that omission intentional. The chosen
// script-src 'self' (no 'unsafe-inline') is correct for a standard Vite
// production build (external module scripts); a future Vite config that emits
// inline bootstrap scripts would break under this CSP and needs a
// production smoke check of the embedded build.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		web.SetSecurityHeaders(w.Header())
		next.ServeHTTP(w, r)
	})
}

// Handler returns the backend router. The JSON API lives under /api/*; the SPA
// (embedded static build) is served at / with client-route fallback. /healthz
// stays at the root for infra probes. Authorization per endpoint: reads need
// viewer, running scans and config writes need operator, deletes need admin.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Auth (public entry points; /api/auth/me needs a session).
	if s.auth != nil {
		mux.HandleFunc("GET /api/auth/login", s.auth.handleLogin)
		mux.HandleFunc("GET /api/auth/callback", s.auth.handleCallback)
		mux.HandleFunc("POST /api/auth/logout", s.sameOrigin(s.auth.handleLogout))
	}
	mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))

	// Scans. Mutations go through s.mutation (authz + a structured audit event);
	// reads stay on requireRole. A scan submit is dispatch, not config.
	mux.HandleFunc("GET /api/scans", s.requireRole(RoleViewer, s.handleListScans))
	mux.HandleFunc("POST /api/scans", s.mutation(eventScanDispatched, "scan.create", "scan", RoleOperator, s.handleCreateScan))
	mux.HandleFunc("GET /api/scans/{id}", s.requireRole(RoleViewer, s.handleGetScan))
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.mutation(eventScanDispatched, "scan.cancel", "scan", RoleOperator, s.handleCancelScan))
	mux.HandleFunc("DELETE /api/scans/{id}", s.mutation(eventScanDispatched, "scan.delete", "scan", RoleAdmin, s.handleDeleteScan))
	mux.HandleFunc("GET /api/scans/{id}/findings", s.requireRole(RoleViewer, s.handleListScanFindings))
	mux.HandleFunc("GET /api/scans/{id}/raw", s.requireRole(RoleViewer, s.handleGetScanRaw))
	mux.HandleFunc("GET /api/scans/{id}/log", s.requireRole(RoleViewer, s.handleGetScanLog))

	// Scan bundle (#136): a versioned, round-trippable export of a complete scan.
	// Export is a viewer read; import recreates a scan + findings + lifecycle on
	// this instance and is an operator mutation (audited under scan_imported).
	mux.HandleFunc("GET /api/scans/{id}/export", s.requireRole(RoleViewer, s.handleExportScanBundle))
	mux.HandleFunc("POST /api/scans/import", s.mutation(eventScanImported, "scan.import", "scan", RoleOperator, s.handleImportScanBundle))

	// Findings — the deduplicated, triageable lifecycle entities (§3). Analyst
	// overlays (disposition, severity recast) are mutations → operator; reads → viewer.
	mux.HandleFunc("GET /api/findings", s.requireRole(RoleViewer, s.handleListFindings))
	mux.HandleFunc("GET /api/findings/export", s.requireRole(RoleViewer, s.handleExportFindings))
	mux.HandleFunc("GET /api/findings/{id}", s.requireRole(RoleViewer, s.handleGetFinding))
	mux.HandleFunc("GET /api/occurrences/{id}", s.requireRole(RoleViewer, s.handleGetOccurrence))
	mux.HandleFunc("PATCH /api/findings/{id}/disposition", s.mutation(eventFindingTriaged, "finding.disposition", "finding", RoleOperator, s.handleSetDisposition))
	mux.HandleFunc("PATCH /api/findings/{id}/severity", s.mutation(eventFindingTriaged, "finding.recast", "finding", RoleOperator, s.handleRecastSeverity))

	// Targets (config)
	mux.HandleFunc("GET /api/targets", s.requireRole(RoleViewer, s.handleListTargets))
	mux.HandleFunc("POST /api/targets", s.mutation(eventConfigChanged, "target.create", "target", RoleOperator, s.handleCreateTarget))
	mux.HandleFunc("GET /api/targets/{id}", s.requireRole(RoleViewer, s.handleGetTarget))
	mux.HandleFunc("PUT /api/targets/{id}", s.mutation(eventConfigChanged, "target.update", "target", RoleOperator, s.handleUpdateTarget))
	mux.HandleFunc("DELETE /api/targets/{id}", s.mutation(eventConfigChanged, "target.delete", "target", RoleAdmin, s.handleDeleteTarget))

	// Scanner nodes (#22) — the DB-backed dispatch registry. Reads → viewer;
	// create/update/delete → admin (managing scan infrastructure), audited as
	// config changes. Nodes never call the backend; the admin manages them here.
	mux.HandleFunc("GET /api/nodes", s.requireRole(RoleViewer, s.handleListNodes))
	mux.HandleFunc("POST /api/nodes", s.mutation(eventConfigChanged, "scanner_node.create", "scanner_node", RoleAdmin, s.handleCreateNode))
	mux.HandleFunc("GET /api/nodes/{id}", s.requireRole(RoleViewer, s.handleGetNode))
	mux.HandleFunc("PUT /api/nodes/{id}", s.mutation(eventConfigChanged, "scanner_node.update", "scanner_node", RoleAdmin, s.handleUpdateNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", s.mutation(eventConfigChanged, "scanner_node.delete", "scanner_node", RoleAdmin, s.handleDeleteNode))
	// Admin "sync now" (#85): push the current full template catalog to one node.
	mux.HandleFunc("POST /api/nodes/{id}/templates/sync", s.mutation(eventConfigChanged, "scanner_node.templates_sync", "scanner_node", RoleAdmin, s.handleSyncNodeTemplates))

	// Schedules (config) — cron-driven scans. Reads → viewer; create/edit/run →
	// operator; delete → admin (matches targets/template-sets). Run is a dispatch.
	mux.HandleFunc("GET /api/schedules", s.requireRole(RoleViewer, s.handleListSchedules))
	mux.HandleFunc("POST /api/schedules", s.mutation(eventConfigChanged, "schedule.create", "schedule", RoleOperator, s.handleCreateSchedule))
	mux.HandleFunc("GET /api/schedules/{id}", s.requireRole(RoleViewer, s.handleGetSchedule))
	mux.HandleFunc("PUT /api/schedules/{id}", s.mutation(eventConfigChanged, "schedule.update", "schedule", RoleOperator, s.handleUpdateSchedule))
	mux.HandleFunc("POST /api/schedules/{id}/run", s.mutation(eventScanDispatched, "schedule.run", "schedule", RoleOperator, s.handleRunSchedule))
	mux.HandleFunc("DELETE /api/schedules/{id}", s.mutation(eventConfigChanged, "schedule.delete", "schedule", RoleAdmin, s.handleDeleteSchedule))

	// Scan policies (config) — reusable rate/concurrency/timeout/max-host-error
	// bundles (#87). Reads → viewer; create/edit → operator; delete → admin
	// (matches targets/template-sets). Audited as config changes.
	mux.HandleFunc("GET /api/scan-policies", s.requireRole(RoleViewer, s.handleListScanPolicies))
	mux.HandleFunc("POST /api/scan-policies", s.mutation(eventConfigChanged, "scan_policy.create", "scan_policy", RoleOperator, s.handleCreateScanPolicy))
	mux.HandleFunc("GET /api/scan-policies/{id}", s.requireRole(RoleViewer, s.handleGetScanPolicy))
	mux.HandleFunc("PUT /api/scan-policies/{id}", s.mutation(eventConfigChanged, "scan_policy.update", "scan_policy", RoleOperator, s.handleUpdateScanPolicy))
	mux.HandleFunc("DELETE /api/scan-policies/{id}", s.mutation(eventConfigChanged, "scan_policy.delete", "scan_policy", RoleAdmin, s.handleDeleteScanPolicy))

	// Template catalog (#85). Reads (browse/search/detail, sync history) → viewer.
	// Only custom templates are writable; upstream rows are owned by the syncer and
	// the store rejects mutating them (ErrTemplateReadOnly). Create/edit → operator,
	// delete → admin (matches targets/template-sets). Audited as config changes.
	// Literal sync routes are more specific than /{id}, so ServeMux routes them
	// first — no real Nuclei template id collides with them.
	mux.HandleFunc("GET /api/templates", s.requireRole(RoleViewer, s.handleListTemplates))
	mux.HandleFunc("GET /api/templates/ids", s.requireRole(RoleViewer, s.handleListTemplateIDs))
	mux.HandleFunc("GET /api/templates/export", s.requireRole(RoleViewer, s.handleExportTemplates))
	mux.HandleFunc("POST /api/templates/import", s.mutation(eventConfigChanged, "templates.import", "template_archive", RoleOperator, s.handleImportTemplates))
	mux.HandleFunc("GET /api/templates/sync", s.requireRole(RoleViewer, s.handleGetTemplateSync))
	mux.HandleFunc("POST /api/templates/sync", s.mutation(eventConfigChanged, "templates.sync_requested", "template_sync", RoleOperator, s.handleRequestTemplateSync))
	mux.HandleFunc("GET /api/templates/sync-runs", s.requireRole(RoleViewer, s.handleListTemplateSyncRuns))
	mux.HandleFunc("POST /api/templates", s.mutation(eventConfigChanged, "template.create", "template", RoleOperator, s.handleCreateTemplate))
	mux.HandleFunc("GET /api/templates/{id}", s.requireRole(RoleViewer, s.handleGetTemplate))
	mux.HandleFunc("PUT /api/templates/{id}", s.mutation(eventConfigChanged, "template.update", "template", RoleOperator, s.handleUpdateTemplate))
	mux.HandleFunc("DELETE /api/templates/{id}", s.mutation(eventConfigChanged, "template.delete", "template", RoleAdmin, s.handleDeleteTemplate))

	// Template sets (config)
	mux.HandleFunc("GET /api/template-sets", s.requireRole(RoleViewer, s.handleListTemplateSets))
	mux.HandleFunc("POST /api/template-sets/import", s.mutation(eventConfigChanged, "templates.import", "template_set_archive", RoleOperator, s.handleImportTemplateSet))
	mux.HandleFunc("POST /api/template-sets", s.mutation(eventConfigChanged, "template_set.create", "template_set", RoleOperator, s.handleCreateTemplateSet))
	mux.HandleFunc("GET /api/template-sets/{id}", s.requireRole(RoleViewer, s.handleGetTemplateSet))
	mux.HandleFunc("GET /api/template-sets/{id}/export", s.requireRole(RoleViewer, s.handleExportTemplateSet))
	mux.HandleFunc("PUT /api/template-sets/{id}", s.mutation(eventConfigChanged, "template_set.update", "template_set", RoleOperator, s.handleUpdateTemplateSet))
	mux.HandleFunc("DELETE /api/template-sets/{id}", s.mutation(eventConfigChanged, "template_set.delete", "template_set", RoleAdmin, s.handleDeleteTemplateSet))

	// Explicit membership (#85): a set curated as a list of catalog templates.
	// Reads → viewer; membership edits → operator, audited as config changes.
	mux.HandleFunc("GET /api/template-sets/{id}/members", s.requireRole(RoleViewer, s.handleListTemplateSetMembers))
	mux.HandleFunc("PUT /api/template-sets/{id}/members", s.mutation(eventConfigChanged, "template_set.members_replace", "template_set", RoleOperator, s.handleReplaceTemplateSetMembers))
	mux.HandleFunc("POST /api/template-sets/{id}/members", s.mutation(eventConfigChanged, "template_set.members_add", "template_set", RoleOperator, s.handleAddTemplateSetMembers))
	mux.HandleFunc("DELETE /api/template-sets/{id}/members/{templateId}", s.mutation(eventConfigChanged, "template_set.members_remove", "template_set", RoleOperator, s.handleRemoveTemplateSetMember))
	mux.HandleFunc("GET /api/template-sets/{id}/exclusions", s.requireRole(RoleViewer, s.handleListTemplateSetExclusions))
	mux.HandleFunc("PUT /api/template-sets/{id}/exclusions", s.mutation(eventConfigChanged, "template_set.exclusions_replace", "template_set", RoleOperator, s.handleReplaceTemplateSetExclusions))

	// Service accounts (#70) — NSC-local API-token identities for headless
	// automation. Managing these credentials is admin-only; create/rotate/revoke
	// are audited under a dedicated security event id. The token itself is only
	// ever returned in the create/rotate response body, never on list.
	mux.HandleFunc("GET /api/service-accounts", s.requireRole(RoleAdmin, s.handleListServiceAccounts))
	mux.HandleFunc("POST /api/service-accounts", s.mutation(eventServiceAccountChanged, "service_account.create", "service_account", RoleAdmin, s.handleCreateServiceAccount))
	mux.HandleFunc("POST /api/service-accounts/{id}/rotate", s.mutation(eventServiceAccountChanged, "service_account.rotate", "service_account", RoleAdmin, s.handleRotateServiceAccount))
	mux.HandleFunc("DELETE /api/service-accounts/{id}", s.mutation(eventServiceAccountChanged, "service_account.revoke", "service_account", RoleAdmin, s.handleDeleteServiceAccount))

	// Sessions (#189) — server-side BFF sessions. Listing and revocation are
	// admin-only so an administrator can terminate a user's sessions immediately
	// on offboarding or role demotion, without waiting for SESSION_TTL expiry.
	// Single-session delete uses the stored hash id returned by the list;
	// bulk delete uses ?subject=. Both are audited as session_revoked.
	mux.HandleFunc("GET /api/sessions", s.requireRole(RoleAdmin, s.handleListSessions))
	mux.HandleFunc("DELETE /api/sessions/{id}", s.mutation(eventSessionRevoked, "session.revoke", "session", RoleAdmin, s.handleDeleteSession))
	mux.HandleFunc("DELETE /api/sessions", s.mutation(eventSessionRevoked, "session.revoke_by_subject", "session", RoleAdmin, s.handleDeleteSessions))

	// Global app settings (#95) — the scan-retention policy. Admin-only surface;
	// the read is admin too (it's an infrastructure config page, not a viewer
	// read). The write is audited as a config change.
	mux.HandleFunc("GET /api/settings", s.requireRole(RoleAdmin, s.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", s.mutation(eventConfigChanged, "settings.update", "settings", RoleAdmin, s.handleUpdateSettings))

	// Unknown /api/* paths get a JSON-ish 404 rather than the SPA's index.html.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	// Everything else: the embedded SPA (falls back to index.html for client routes).
	mux.Handle("/", s.spa)

	return securityHeaders(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMe returns the authenticated caller's identity (for the SPA to render).
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, identityFrom(r.Context()))
}

// createScanRequest launches a scan by selecting an approved stored target and a
// reusable scan policy (#137). There is no ad-hoc host/spec path: target_id is an
// FK-backed allowlist record, so scope remains guaranteed by construction.
type createScanRequest struct {
	ScanPolicyID string `json:"scan_policy_id"`
	TargetID     string `json:"target_id"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	spec, link, err := s.buildScanSpec(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	addAuditFields(r,
		slog.String("scan_policy_id", link.ScanPolicyID),
		slog.String("target_id", link.TargetID),
	)

	scanID, err := s.orch.Submit(r.Context(), spec, link)
	if err != nil {
		if errors.Is(err, ErrScanCapacity) {
			http.Error(w, "scan admission capacity exhausted; retry later", http.StatusTooManyRequests)
			return
		}
		s.serverError(w, "submit scan", err)
		return
	}
	addAuditFields(r, slog.String("scan_id", scanID))
	writeJSON(w, http.StatusAccepted, map[string]string{"scan_id": scanID})
}

// buildScanSpec resolves a createScanRequest into a concrete spec + config link.
// Every scan names both its approved scope and reusable configuration.
func (s *Server) buildScanSpec(ctx context.Context, req createScanRequest) (types.ScanSpec, store.ScanLink, error) {
	if req.ScanPolicyID == "" {
		return types.ScanSpec{}, store.ScanLink{}, errors.New("scan_policy_id is required")
	}
	if req.TargetID == "" {
		return types.ScanSpec{}, store.ScanLink{}, errors.New("target_id is required")
	}
	return s.resolvePolicySpec(ctx, req.ScanPolicyID, req.TargetID)
}

// resolvePolicySpec builds a concrete spec from a target-independent policy and
// an approved stored target. Shared by ad-hoc and scheduled dispatch. The scope
// guardrail (§6) holds because targetID can reference only the target allowlist;
// callers still cannot submit an arbitrary host/spec.
func (s *Server) resolvePolicySpec(ctx context.Context, policyID, targetID string) (types.ScanSpec, store.ScanLink, error) {
	pol, err := s.store.GetScanPolicy(ctx, policyID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("unknown scan_policy_id %q", policyID)
		}
		return types.ScanSpec{}, store.ScanLink{}, err
	}
	spec, link, err := s.resolveConfigSpec(ctx, targetID, pol.TemplateSetID)
	if err != nil {
		return types.ScanSpec{}, store.ScanLink{}, err
	}
	spec.Options = overlayScanPolicy(spec.Options, pol)
	link.ScanPolicyID = pol.ID
	return spec, link, nil
}

// resolveConfigSpec builds a scan spec + config link from a stored target and an
// required template set. The scan carries concrete ids plus the digest of the
// full active catalog bundle already distributed to the node. Catalog-derived
// sets resolve from the active catalog; exclude mode subtracts its exclusions.
// An empty exact or fully-excluded exclude set fails closed.
func (s *Server) resolveConfigSpec(ctx context.Context, targetID, templateSetID string) (types.ScanSpec, store.ScanLink, error) {
	target, err := s.store.GetTarget(ctx, targetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("unknown target_id %q", targetID)
		}
		return types.ScanSpec{}, store.ScanLink{}, err
	}
	spec := types.ScanSpec{Targets: types.DeduplicateTargetHosts(target.Hosts), Options: defaultOptions()}
	ts, err := s.store.GetTemplateSet(ctx, templateSetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("unknown template_set_id %q", templateSetID)
		}
		return types.ScanSpec{}, store.ScanLink{}, err
	}
	if ts.Mode == store.TemplateSetModeExact && ts.MemberCount == 0 {
		return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("template set %q is empty", ts.Name)
	}
	link := store.ScanLink{TargetID: target.ID, TemplateSetID: ts.ID}

	var selectedIDs []string
	if ts.Mode == store.TemplateSetModeExact {
		members, err := s.store.ListTemplateSetMembers(ctx, ts.ID)
		if err != nil {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("list template set members: %w", err)
		}
		if len(members) == 0 {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("template set %q is empty", ts.Name)
		}
		var unavailable []string
		for _, member := range members {
			if member.Availability != "active" {
				unavailable = append(unavailable, member.ID)
				continue
			}
			selectedIDs = append(selectedIDs, member.ID)
		}
		if len(unavailable) > 0 {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf(
				"template set %q contains unavailable templates: %s — update its explicit selection first",
				ts.Name, strings.Join(unavailable, ", "),
			)
		}
	}

	entries, err := s.store.ActiveTemplateBundleEntries(ctx)
	if err != nil {
		return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("read active template catalog: %w", err)
	}
	if len(entries) == 0 {
		return types.ScanSpec{}, store.ScanLink{}, errors.New("active template catalog is empty")
	}
	if ts.Mode == store.TemplateSetModeExclude {
		excludedIDs, err := s.store.ListTemplateSetExclusionIDs(ctx, ts.ID)
		if err != nil {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("list template set exclusions: %w", err)
		}
		excluded := make(map[string]struct{}, len(excludedIDs))
		for _, id := range excludedIDs {
			excluded[id] = struct{}{}
		}
		selectedIDs = make([]string, 0, len(entries))
		for _, entry := range entries {
			if _, ok := excluded[entry.ID]; ok {
				continue
			}
			selectedIDs = append(selectedIDs, entry.ID)
		}
		if len(selectedIDs) == 0 {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf("template set %q resolves to no active templates after exclusions", ts.Name)
		}
	} else if ts.Mode == store.TemplateSetModeExact {
		active := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			active[entry.ID] = struct{}{}
		}
		var unavailable []string
		for _, id := range selectedIDs {
			if _, ok := active[id]; !ok {
				unavailable = append(unavailable, id)
			}
		}
		if len(unavailable) > 0 {
			return types.ScanSpec{}, store.ScanLink{}, fmt.Errorf(
				"template set contains unavailable templates: %s — update its explicit selection first",
				strings.Join(unavailable, ", "),
			)
		}
	} else {
		selectedIDs = make([]string, 0, len(entries))
		for _, entry := range entries {
			selectedIDs = append(selectedIDs, entry.ID)
		}
	}
	spec.Templates.TemplateIDs = selectedIDs
	spec.Templates.TemplatesCommit = types.BundleDigest(entries)
	return spec, link, nil
}

// overlayScanPolicy overlays a scan policy's execution knobs onto opts (a base
// already carrying defaultOptions): each of the policy's non-nil knobs replaces
// the corresponding base option, others pass through untouched — so a policy can
// tune just one knob (e.g. raise max_host_error) and leave the rest. Pure, so the
// override precedence is testable without a database round-trip.
func overlayScanPolicy(opts types.ScanOptions, p store.ScanPolicy) types.ScanOptions {
	if p.RateLimit != nil {
		opts.RateLimit = *p.RateLimit
	}
	if p.Concurrency != nil {
		opts.Concurrency = *p.Concurrency
	}
	if p.TimeoutSec != nil {
		opts.TimeoutSec = *p.TimeoutSec
	}
	if p.MaxHostError != nil {
		opts.MaxHostError = *p.MaxHostError
	}
	// Discovery (#86): a nil DiscoveryEnabled means "use the default", which is ON
	// — matching the column default, so a policy that predates discovery still
	// gets it. The node treats the boolean literally; the default lives here + the
	// DB, never on the (stateless) node.
	enabled := true
	if p.DiscoveryEnabled != nil {
		enabled = *p.DiscoveryEnabled
	}
	d := types.DiscoveryOptions{
		Enabled:       enabled,
		HostDiscovery: p.DiscoveryHostDiscovery,
		ScanType:      p.DiscoveryScanType,
		Ports:         p.DiscoveryPorts,
	}
	if p.DiscoveryTimeoutSec != nil {
		d.TimeoutSec = *p.DiscoveryTimeoutSec
	}
	if p.DiscoveryRate != nil {
		d.Rate = *p.DiscoveryRate
	}
	if p.DiscoveryProbeTimeoutMs != nil {
		d.ProbeTimeoutMs = *p.DiscoveryProbeTimeoutMs
	}
	if p.DiscoveryRetries != nil {
		d.Retries = *p.DiscoveryRetries
	}
	opts.Discovery = &d
	return opts
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.store.ListScans(r.Context(), limit)
	if err != nil {
		s.serverError(w, "list scans", err)
		return
	}
	if rows == nil {
		rows = []store.ScanRow{}
	}
	// Attach live progress (#66) to running scans from the orchestrator's cache.
	for i := range rows {
		if rows[i].State == string(types.ScanRunning) {
			rows[i].Progress = s.orch.Progress(rows[i].ID)
		}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	row, err := s.store.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		s.serverError(w, "get scan", err)
		return
	}
	if row.State == string(types.ScanRunning) {
		row.Progress = s.orch.Progress(row.ID)
		// Discovered endpoints aren't persisted until completion; serve the live
		// cache so the scanning phase can show them (#86).
		if len(row.DiscoveredTargets) == 0 {
			row.DiscoveredTargets = s.orch.Discovered(row.ID)
		}
	}
	writeJSON(w, http.StatusOK, row)
}

// handleCancelScan stops a queued/running scan (operator). It flips the scan to
// cancelled (the DB update is the authority on the transition), then best-effort
// signals the node to abort the in-progress run. A scan that isn't in a
// cancellable state gets 409; an unknown scan gets 404.
func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := identityFrom(r.Context())
	reason := "cancelled by " + firstNonEmpty(actor.Name, actor.Email, actor.Subject, "operator")
	nodeScanID, cancelled, err := s.store.CancelScan(r.Context(), id, reason)
	if err != nil {
		s.serverError(w, "cancel scan", err)
		return
	}
	if !cancelled {
		// Not cancellable: distinguish gone (404) from already-terminal (409).
		if _, gerr := s.store.GetScan(r.Context(), id); errors.Is(gerr, store.ErrNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		http.Error(w, "scan is not in a cancellable state", http.StatusConflict)
		return
	}
	// Detached from the request so a client disconnect can't leave the node
	// running; the DB already reflects cancelled either way.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		s.orch.SignalNodeCancel(ctx, nodeScanID)
	}()
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteScan removes a scan record (admin). Its findings occurrences
// cascade; lifecycle references are set NULL by the schema. A queued/running
// scan can't be deleted (409) — cancel it first. The archived raw object is
// purged best-effort (storage cleanup must never fail the delete, since Postgres
// is already the system of record and the row is gone).
func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rawKey, logKey, err := s.store.DeleteScan(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			http.Error(w, "scan not found", http.StatusNotFound)
		case errors.Is(err, store.ErrConflict):
			http.Error(w, "cancel the scan before deleting it", http.StatusConflict)
		default:
			s.serverError(w, "delete scan", err)
		}
		return
	}
	if s.archive != nil {
		for _, key := range []string{rawKey, logKey} {
			if key == "" {
				continue
			}
			if err := s.archive.Delete(r.Context(), key); err != nil {
				s.log.Warn("purge archived scan object", "scan_id", id, "key", key, "err", err)
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetScanRaw streams a scan's archived verbatim Nuclei output (out.jsonl)
// from object storage, through the BFF so it stays behind the session cookie
// (same trust model as the exports — no presigned URLs leaking the bucket).
func (s *Server) handleGetScanRaw(w http.ResponseWriter, r *http.Request) {
	if s.archive == nil {
		http.Error(w, "object storage is not configured", http.StatusNotFound)
		return
	}
	id := r.PathValue("id")
	key, err := s.store.ScanRawKey(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		s.serverError(w, "get scan raw key", err)
		return
	}
	if key == "" {
		http.Error(w, "no archived output for this scan", http.StatusNotFound)
		return
	}

	obj, err := s.archive.Get(r.Context(), key)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			http.Error(w, "archived output is missing from storage", http.StatusNotFound)
			return
		}
		s.serverError(w, "get archived raw output", err)
		return
	}
	defer obj.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%s.jsonl"`, id))
	if _, err := io.Copy(w, obj); err != nil {
		s.log.Warn("stream raw archive", "scan_id", id, "err", err)
	}
}

// handleGetScanLog streams a scan's archived execution log (Nuclei's
// stdout/stderr, #94) from object storage, through the BFF like handleGetScanRaw
// — same-origin behind the session cookie, no presigned URLs.
func (s *Server) handleGetScanLog(w http.ResponseWriter, r *http.Request) {
	if s.archive == nil {
		http.Error(w, "object storage is not configured", http.StatusNotFound)
		return
	}
	id := r.PathValue("id")
	key, err := s.store.ScanLogKey(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		s.serverError(w, "get scan log key", err)
		return
	}
	if key == "" {
		http.Error(w, "no archived log for this scan", http.StatusNotFound)
		return
	}

	obj, err := s.archive.Get(r.Context(), key)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			http.Error(w, "archived log is missing from storage", http.StatusNotFound)
			return
		}
		s.serverError(w, "get archived log", err)
		return
	}
	defer obj.Close()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%s.log"`, id))
	if _, err := io.Copy(w, obj); err != nil {
		s.log.Warn("stream log archive", "scan_id", id, "err", err)
	}
}

// pageParams parses the shared limit/offset pagination knobs.
func pageParams(q url.Values) (limit, offset int) {
	limit, _ = strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset, _ = strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// findingsPage is the paginated envelope returned by GET /api/findings (the
// deduplicated lifecycle view).
type findingsPage struct {
	Items  []store.LifecycleRow `json:"items"`
	Total  int                  `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

const maxFindingFilterBytes = 64 << 10

// findingQueryFromRequest parses the shared findings filter (used by both the
// list and export endpoints, so they stay in lockstep). The structured filter
// travels as one JSON `filter` param (the condition-builder tree). When absent,
// it falls back to the legacy flat params (`severity=…&host=…`) compiled into a
// single AND-group, so old bookmarks and API callers keep working.
func findingQueryFromRequest(q url.Values) (store.FindingQuery, error) {
	if err := validateFindingFilterQueryParams(q); err != nil {
		return store.FindingQuery{}, err
	}
	raw := q.Get("filter")
	if raw = strings.TrimSpace(raw); raw != "" {
		var fq store.FindingQuery
		if err := json.Unmarshal([]byte(raw), &fq); err != nil {
			return store.FindingQuery{}, fmt.Errorf("invalid filter: %w", err)
		}
		return fq, nil
	}
	return legacyFlatQuery(q), nil
}

var findingFilterQueryParamKeys = []string{
	"filter", "q", "severity", "state", "disposition", "target_id", "host", "cve", "tag",
}

// validateFindingFilterQueryParams bounds the raw values before the legacy
// query parser can split them into slices. The structured filter is singular;
// duplicate values are ambiguous and are rejected instead of silently ignoring
// all but the first one.
func validateFindingFilterQueryParams(q url.Values) error {
	if values, ok := q["filter"]; ok && len(values) > 1 {
		return errors.New("only one filter parameter is allowed")
	}
	total := 0
	for _, key := range findingFilterQueryParamKeys {
		for _, value := range q[key] {
			total += len(value)
			if total > maxFindingFilterBytes {
				return fmt.Errorf("filter exceeds %d-byte limit", maxFindingFilterBytes)
			}
		}
	}
	return nil
}

// legacyFlatQuery compiles the pre-condition-builder query params into a single
// AND-group (any-of within each field), preserving backwards compatibility.
func legacyFlatQuery(q url.Values) store.FindingQuery {
	var conds []store.FindingCondition
	add := func(field, op string, vals []string) {
		if len(vals) > 0 {
			conds = append(conds, store.FindingCondition{Field: field, Op: op, Values: vals})
		}
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		add("name", "contains", []string{v})
	}
	add("severity", "any_of", multiCSV(q, "severity"))
	add("state", "any_of", multiCSV(q, "state"))
	add("disposition", "any_of", multiCSV(q, "disposition"))
	add("target", "any_of", multiCSV(q, "target_id"))
	add("host", "contains", multiCSV(q, "host"))
	add("cve", "contains", multiCSV(q, "cve"))
	add("tag", "any_of", multiCSV(q, "tag"))
	if len(conds) == 0 {
		return store.FindingQuery{}
	}
	return store.FindingQuery{Groups: []store.FindingGroup{{Conditions: conds}}}
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := pageParams(q)
	fq, err := findingQueryFromRequest(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := store.ValidateFindingQuery(fq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows, total, err := s.searcher.ListLifecycle(r.Context(), fq, limit, offset)
	if err != nil {
		s.serverError(w, "list lifecycle findings", err)
		return
	}
	if rows == nil {
		rows = []store.LifecycleRow{}
	}
	writeJSON(w, http.StatusOK, findingsPage{Items: rows, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid finding id", http.StatusBadRequest)
		return
	}
	d, err := s.store.GetLifecycleFinding(r.Context(), id)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleGetOccurrence(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid occurrence id", http.StatusBadRequest)
		return
	}
	detail, err := s.store.GetOccurrence(r.Context(), id)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// actorFrom returns a stable identifier for the authenticated caller (email,
// falling back to subject) to stamp on an audit field.
func actorFrom(r *http.Request) string {
	id := identityFrom(r.Context())
	if id.Email != "" {
		return id.Email
	}
	return id.Subject
}

// setDispositionRequest is the body of PATCH /api/findings/{id}/disposition.
// AcceptExpiresAt is honoured only for the "accepted" disposition (Accept Risk).
type setDispositionRequest struct {
	Disposition     string     `json:"disposition"`
	Note            string     `json:"note"`
	AcceptExpiresAt *time.Time `json:"accept_expires_at"`
}

func (s *Server) handleSetDisposition(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid finding id", http.StatusBadRequest)
		return
	}
	var req setDispositionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !store.ValidDisposition(req.Disposition) {
		http.Error(w, "invalid disposition (want one of: none, false_positive, accepted)", http.StatusBadRequest)
		return
	}
	if err := s.store.SetDisposition(r.Context(), id, req.Disposition, strings.TrimSpace(req.Note), actorFrom(r), req.AcceptExpiresAt); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	s.writeFinding(w, r, id)
}

// recastSeverityRequest is the body of PATCH /api/findings/{id}/severity. An empty
// severity clears the recast (reverting to the scan-observed severity).
type recastSeverityRequest struct {
	Severity string `json:"severity"`
	Note     string `json:"note"`
}

func (s *Server) handleRecastSeverity(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid finding id", http.StatusBadRequest)
		return
	}
	var req recastSeverityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	sev := strings.TrimSpace(req.Severity)
	if sev != "" && !store.ValidSeverity(sev) {
		http.Error(w, "invalid severity (want one of: critical, high, medium, low, info — or empty to clear)", http.StatusBadRequest)
		return
	}
	if err := s.store.RecastSeverity(r.Context(), id, sev, strings.TrimSpace(req.Note), actorFrom(r)); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	s.writeFinding(w, r, id)
}

// writeFinding re-reads a lifecycle finding and writes it as the response (the
// updated entity returned by the disposition/recast mutations).
func (s *Server) writeFinding(w http.ResponseWriter, r *http.Request, id int64) {
	d, err := s.store.GetLifecycleFinding(r.Context(), id)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// handleListScanFindings returns the immutable per-scan occurrences observed by
// one scan (the scan-detail view), paginated + filterable like the main list.
func (s *Server) handleListScanFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if err := validateFindingFilterQueryParams(q); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limit, offset := pageParams(q)
	filter := store.FindingFilter{
		ScanID:     r.PathValue("id"),
		Query:      strings.TrimSpace(q.Get("q")),
		Severities: splitCSV(q.Get("severity")),
		Host:       strings.TrimSpace(q.Get("host")),
		CVE:        strings.TrimSpace(q.Get("cve")),
		Tag:        strings.TrimSpace(q.Get("tag")),
		Limit:      limit,
		Offset:     offset,
	}
	if err := store.ValidateFindingFilter(filter); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows, total, err := s.store.ListFindings(r.Context(), filter)
	if err != nil {
		s.serverError(w, "list scan findings", err)
		return
	}
	if rows == nil {
		rows = []store.FindingRow{}
	}
	writeJSON(w, http.StatusOK, occurrencesPage{Items: rows, Total: total, Limit: limit, Offset: offset})
}

// occurrencesPage is the paginated envelope for per-scan occurrences.
type occurrencesPage struct {
	Items  []store.FindingRow `json:"items"`
	Total  int                `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}

// splitCSV splits a comma-separated query value, trimming spaces and dropping empties.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// multiCSV collects a multi-value query param: every repetition of the key, each
// itself split on commas (so `k=a&k=b`, `k=a,b`, and `k=a` all work). Empties are
// dropped; returns nil when absent. Duplicate values are de-duplicated so a
// repeated pick doesn't bloat the bind array.
func multiCSV(q url.Values, key string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range q[key] {
		for _, p := range splitCSV(raw) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
