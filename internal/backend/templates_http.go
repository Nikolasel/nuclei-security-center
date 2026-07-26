package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/templates"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// maxTemplateYAML caps a custom-template upload. Nuclei templates are small
// (a few KB); this is generous while bounding memory on a bad request (CWE-770).
const maxTemplateYAML = 1 << 20 // 1 MiB

// customTemplateValidationTimeout bounds node selection plus validation across
// all healthy candidates; a request cannot accumulate one client timeout per
// registered node.
const customTemplateValidationTimeout = 40 * time.Second

// customIDPattern constrains a custom template's Nuclei id so it is a safe,
// single-path-segment slug: it becomes the {id} route param and the synthesized
// custom/<id>.yaml catalog path, so slashes, spaces, and dots-only are rejected.
var customIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

// templateResponse is the single-template envelope (detail / create / update).
// It embeds the catalog row and adds the yaml body, which the Template struct
// itself hides (`json:"-"`) so list responses stay lean.
type templateResponse struct {
	store.Template
	YAML       string                          `json:"yaml"`
	Validation *types.TemplateValidationResult `json:"validation,omitempty"`
}

func templateDetail(t store.Template) templateResponse {
	return templateResponse{Template: t, YAML: t.YAML}
}

// templatesPage is the paginated envelope for GET /api/templates.
type templatesPage struct {
	Items  []store.Template `json:"items"`
	Total  int              `json:"total"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
}

type templateIDsResponse struct {
	IDs []string `json:"ids"`
}

func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if src := q.Get("source"); src != "" && src != "upstream" && src != "custom" {
		http.Error(w, "source must be 'upstream' or 'custom'", http.StatusBadRequest)
		return
	}
	if sortBy := q.Get("sort"); sortBy != "" && sortBy != "name" && sortBy != "inserted" {
		http.Error(w, "sort must be 'name' or 'inserted'", http.StatusBadRequest)
		return
	}
	limit, offset := pageParams(q)
	f := store.TemplateFilter{
		Source:             q.Get("source"),
		Severities:         multiCSV(q, "severity"),
		Tags:               multiCSV(q, "tag"),
		CVEOnly:            q.Get("cve") == "true",
		Query:              q.Get("q"),
		Sort:               q.Get("sort"),
		IncludeUnavailable: q.Get("include_unavailable") == "true",
	}
	items, total, err := s.store.ListTemplates(r.Context(), f, limit, offset)
	if err != nil {
		s.serverError(w, "list templates", err)
		return
	}
	if items == nil {
		items = []store.Template{}
	}
	writeJSON(w, http.StatusOK, templatesPage{Items: items, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleListTemplateIDs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if src := q.Get("source"); src != "" && src != "upstream" && src != "custom" {
		http.Error(w, "source must be 'upstream' or 'custom'", http.StatusBadRequest)
		return
	}
	if sortBy := q.Get("sort"); sortBy != "" && sortBy != "name" && sortBy != "inserted" {
		http.Error(w, "sort must be 'name' or 'inserted'", http.StatusBadRequest)
		return
	}
	ids, err := s.store.ListTemplateIDs(r.Context(), store.TemplateFilter{
		Source:             q.Get("source"),
		Severities:         multiCSV(q, "severity"),
		Tags:               multiCSV(q, "tag"),
		CVEOnly:            q.Get("cve") == "true",
		Query:              q.Get("q"),
		Sort:               q.Get("sort"),
		IncludeUnavailable: q.Get("include_unavailable") == "true",
	})
	if err != nil {
		s.serverError(w, "list template ids", err)
		return
	}
	if ids == nil {
		ids = []string{}
	}
	writeJSON(w, http.StatusOK, templateIDsResponse{IDs: ids})
}

func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetTemplate(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, templateDetail(t))
}

func (s *Server) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	body, ok := readTemplateBody(w, r)
	if !ok {
		return
	}
	t, ok := s.parseCustomTemplate(w, body)
	if !ok {
		return
	}
	validation, ok := s.authorizeCustomTemplate(w, r, body)
	if !ok {
		return
	}
	t.CreatedBy = identityFrom(r.Context()).Subject
	created, err := s.store.CreateCustomTemplate(r.Context(), t)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	response := templateDetail(created)
	response.Validation = &validation
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	body, ok := readTemplateBody(w, r)
	if !ok {
		return
	}
	t, ok := s.parseCustomTemplate(w, body)
	if !ok {
		return
	}
	// The id lives inside the YAML and is the primary key; changing it on edit
	// would be an identity swap, not an update. Require the body id to match the
	// URL so the PK stays stable.
	if t.ID != r.PathValue("id") {
		http.Error(w, "template id in body does not match the URL", http.StatusBadRequest)
		return
	}
	validation, ok := s.authorizeCustomTemplate(w, r, body)
	if !ok {
		return
	}
	updated, err := s.store.UpdateCustomTemplate(r.Context(), r.PathValue("id"), t)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	response := templateDetail(updated)
	response.Validation = &validation
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) authorizeCustomTemplate(w http.ResponseWriter, r *http.Request, yaml []byte) (types.TemplateValidationResult, bool) {
	if s.templateValidator == nil {
		s.serviceUnavailable(w, "validate custom template", errTemplateValidatorUnavailable)
		return types.TemplateValidationResult{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), customTemplateValidationTimeout)
	defer cancel()
	result, err := s.templateValidator(ctx, yaml)
	if err != nil {
		s.serviceUnavailable(w, "validate custom template", err)
		return types.TemplateValidationResult{}, false
	}
	if !result.Valid {
		message := strings.Join(result.Errors, "; ")
		if message == "" {
			message = "Nuclei rejected the template"
		}
		http.Error(w, "nuclei validation failed: "+message, http.StatusBadRequest)
		return types.TemplateValidationResult{}, false
	}
	return result, true
}

func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteCustomTemplate(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetTemplateSync(w http.ResponseWriter, r *http.Request) {
	status := TemplateSyncStatus{Enabled: false}
	if s.templateSyncer == nil {
		if s.store == nil {
			writeJSON(w, http.StatusOK, status)
			return
		}
	} else {
		status = s.templateSyncer.Status()
	}
	entries, err := s.store.ActiveTemplateBundleEntries(r.Context())
	if err != nil {
		s.serverError(w, "read active template catalog digest", err)
		return
	}
	status.TemplateCount = len(entries)
	if len(entries) > 0 {
		status.TemplatesCommit = types.BundleDigest(entries)
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleRequestTemplateSync(w http.ResponseWriter, _ *http.Request) {
	if s.templateSyncer == nil {
		http.Error(w, "upstream template sync is disabled", http.StatusServiceUnavailable)
		return
	}
	s.templateSyncer.RequestSync()
	writeJSON(w, http.StatusAccepted, map[string]bool{"queued": true})
}

// handleListTemplateSyncRuns backs the Sync view: recent refresh outcomes,
// newest first.
func (s *Server) handleListTemplateSyncRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListTemplateSyncRuns(r.Context(), 20)
	if err != nil {
		s.serverError(w, "list template sync runs", err)
		return
	}
	if runs == nil {
		runs = []store.TemplateSyncRun{}
	}
	writeJSON(w, http.StatusOK, runs)
}

// readTemplateBody reads a raw YAML upload (not JSON) up to maxTemplateYAML,
// rejecting an empty body with 400.
func readTemplateBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTemplateYAML))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	if len(body) == 0 {
		http.Error(w, "empty template body", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

// parseCustomTemplate validates a YAML upload with the same parser the syncer
// uses, then builds a store.Template with a synthesized custom/<id>.yaml path.
// It writes the 400 itself and returns ok=false on any validation failure.
func (s *Server) parseCustomTemplate(w http.ResponseWriter, body []byte) (store.Template, bool) {
	template, err := customTemplateFromYAML(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return store.Template{}, false
	}
	return template, true
}

func customTemplateFromYAML(body []byte) (store.Template, error) {
	// The path passed to Parse is only used for metadata; the authoritative
	// custom path is derived from the parsed id below, so a placeholder is fine.
	// ParseCustom (not Parse) applies the stricter upload checks — known
	// severity + an executable section — that the upstream sync doesn't.
	meta, err := templates.ParseCustom("custom/placeholder.yaml", body)
	if errors.Is(err, templates.ErrNotTemplate) {
		return store.Template{}, errors.New("not a Nuclei template: missing top-level id")
	}
	if err != nil {
		return store.Template{}, fmt.Errorf("invalid template: %w", err)
	}
	if !customIDPattern.MatchString(meta.ID) {
		return store.Template{}, errors.New("template id must be a slug (letters, digits, dot, dash, underscore; no slashes)")
	}
	return store.Template{
		ID: meta.ID, Path: "custom/" + meta.ID + ".yaml", YAML: meta.YAML,
		ContentSHA256: meta.ContentSHA256, Name: meta.Name, Author: meta.Author,
		Severity: meta.Severity, Description: meta.Description, Tags: meta.Tags,
	}, nil
}
