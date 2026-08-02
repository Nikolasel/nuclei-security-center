package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	templatespkg "github.com/Nikolasel/nuclei-security-center/internal/templates"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

const (
	portableArchiveVersion = 1
	maxPortableUpload      = 64 << 20  // 64 MiB compressed/JSON request
	maxPortableExpanded    = 256 << 20 // 256 MiB decompressed YAML
	maxPortableFiles       = 25000
)

type portableTemplateMeta struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Path     string `json:"path"`
	Revision int    `json:"revision"`
	SHA256   string `json:"sha256"`
}

type portableManifest struct {
	Version   int                    `json:"version"`
	Templates []portableTemplateMeta `json:"templates"`
}

type portableTemplateJSON struct {
	portableTemplateMeta
	YAML string `json:"yaml"`
}

type portableSet struct {
	Name                string                `json:"name"`
	Mode                store.TemplateSetMode `json:"mode,omitempty"`
	TemplateIDs         []string              `json:"template_ids,omitempty"`
	ExcludedTemplateIDs []string              `json:"excluded_template_ids,omitempty"`
	// LegacyDynamicAll accepts archives produced before the explicit mode contract.
	// It is normalized during validation and never emitted in new exports.
	LegacyDynamicAll *bool `json:"dynamic_all,omitempty"`
}

type portableJSONArchive struct {
	Version   int                    `json:"version"`
	Templates []portableTemplateJSON `json:"templates"`
	Set       *portableSet           `json:"set,omitempty"`
}

type parsedPortableArchive struct {
	Templates []portableTemplateJSON
	Set       *portableSet
}

type importRename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type templateImportSummary struct {
	Created         int            `json:"created"`
	Updated         int            `json:"updated"`
	Skipped         int            `json:"skipped"`
	UpstreamIgnored int            `json:"upstream_ignored"`
	Renamed         []importRename `json:"renamed"`
}

type portableImportResponse struct {
	Templates  templateImportSummary                `json:"templates"`
	Validation *types.TemplateBatchValidationResult `json:"validation,omitempty"`
	Set        *store.TemplateSet                   `json:"set,omitempty"`
	SetStatus  string                               `json:"set_status,omitempty"`
}

func (s *Server) handleExportTemplates(w http.ResponseWriter, r *http.Request) {
	ids := uniqueStrings(multiCSV(r.URL.Query(), "ids"))
	if len(ids) == 0 {
		http.Error(w, "at least one template id is required", http.StatusBadRequest)
		return
	}
	templates, err := s.store.GetTemplatesByIDs(r.Context(), ids)
	if err != nil {
		s.serverError(w, "load template export", err)
		return
	}
	if missing := missingTemplateIDs(ids, templates); len(missing) > 0 {
		http.Error(w, "unknown template ids: "+strings.Join(missing, ", "), http.StatusNotFound)
		return
	}
	s.writePortableExport(w, r, "templates", templates, nil)
}

func (s *Server) handleExportTemplateSet(w http.ResponseWriter, r *http.Request) {
	set, err := s.store.GetTemplateSet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	var (
		ids       []string
		templates []store.Template
	)
	if set.Mode == store.TemplateSetModeExact {
		members, err := s.store.ListTemplateSetMembers(r.Context(), set.ID)
		if err != nil {
			s.writeStoreErr(w, err)
			return
		}
		ids = make([]string, len(members))
		for i, member := range members {
			ids[i] = member.ID
		}
		templates, err = s.store.GetTemplatesByIDs(r.Context(), ids)
		if err != nil {
			s.serverError(w, "load template set export", err)
			return
		}
	} else if set.Mode == store.TemplateSetModeExclude {
		exclusions, err := s.store.ListTemplateSetExclusions(r.Context(), set.ID)
		if err != nil {
			s.writeStoreErr(w, err)
			return
		}
		ids = make([]string, len(exclusions))
		for i, exclusion := range exclusions {
			ids[i] = exclusion.ID
		}
		// An exclude set must remain an exclude set on import. Include only the
		// referenced exclusions so custom YAML can travel with the set without
		// freezing the full active catalog.
		templates = exclusions
	}
	setDoc := &portableSet{Name: set.Name, Mode: set.Mode}
	if set.Mode == store.TemplateSetModeExclude {
		setDoc.ExcludedTemplateIDs = ids
	} else if set.Mode == store.TemplateSetModeExact {
		setDoc.TemplateIDs = ids
	}
	s.writePortableExport(w, r, safeDownloadName(set.Name), templates, setDoc)
}

func (s *Server) writePortableExport(
	w http.ResponseWriter,
	r *http.Request,
	name string,
	templates []store.Template,
	set *portableSet,
) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "yaml"
	}
	var (
		data        []byte
		contentType string
		extension   string
		err         error
	)
	switch format {
	case "yaml":
		data, err = buildPortableTarGz(templates, set)
		contentType, extension = "application/gzip", "tar.gz"
	case "json":
		data, err = buildPortableJSON(templates, set)
		contentType, extension = "application/json", "json"
	default:
		http.Error(w, "format must be 'yaml' or 'json'", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, "build template export", err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, name, extension))
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func buildPortableTarGz(templates []store.Template, set *portableSet) ([]byte, error) {
	manifest := portableManifest{Version: portableArchiveVersion, Templates: portableMetadata(templates)}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	closeWith := func(err error) ([]byte, error) {
		_ = tw.Close()
		_ = gz.Close()
		return nil, err
	}
	if err := writeBundleFile(tw, "manifest.json", append(manifestJSON, '\n')); err != nil {
		return closeWith(err)
	}
	for _, template := range sortedTemplates(templates) {
		name, err := portableTemplatePath(template.Source, template.Path)
		if err != nil {
			return closeWith(fmt.Errorf("template %q: %w", template.ID, err))
		}
		if err := writeBundleFile(tw, name, []byte(template.YAML)); err != nil {
			return closeWith(err)
		}
	}
	if set != nil {
		setJSON, err := json.MarshalIndent(set, "", "  ")
		if err != nil {
			return closeWith(err)
		}
		if err := writeBundleFile(tw, "set.json", append(setJSON, '\n')); err != nil {
			return closeWith(err)
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildPortableJSON(templates []store.Template, set *portableSet) ([]byte, error) {
	doc := portableJSONArchive{Version: portableArchiveVersion, Set: set}
	for _, template := range sortedTemplates(templates) {
		doc.Templates = append(doc.Templates, portableTemplateJSON{
			portableTemplateMeta: portableTemplateMeta{
				ID: template.ID, Source: template.Source, Path: template.Path,
				Revision: template.Revision, SHA256: template.ContentSHA256,
			},
			YAML: template.YAML,
		})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func portableMetadata(templates []store.Template) []portableTemplateMeta {
	out := make([]portableTemplateMeta, 0, len(templates))
	for _, template := range sortedTemplates(templates) {
		out = append(out, portableTemplateMeta{
			ID: template.ID, Source: template.Source, Path: template.Path,
			Revision: template.Revision, SHA256: template.ContentSHA256,
		})
	}
	return out
}

func sortedTemplates(in []store.Template) []store.Template {
	out := append([]store.Template(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func portableTemplatePath(source, templatePath string) (string, error) {
	if source != "upstream" && source != "custom" {
		return "", fmt.Errorf("invalid source %q", source)
	}
	clean := path.Clean(strings.ReplaceAll(templatePath, "\\", "/"))
	if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("unsafe path %q", templatePath)
	}
	return path.Join("templates", source, clean), nil
}

func (s *Server) handleImportTemplates(w http.ResponseWriter, r *http.Request) {
	s.handlePortableImport(w, r, false)
}

func (s *Server) handleImportTemplateSet(w http.ResponseWriter, r *http.Request) {
	s.handlePortableImport(w, r, true)
}

func (s *Server) handlePortableImport(w http.ResponseWriter, r *http.Request, requireSet bool) {
	strategy, err := importStrategy(r.URL.Query().Get("on_conflict"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, filename, err := readMultipartFile(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	archive, err := parsePortableArchive(data, filename)
	if err != nil {
		http.Error(w, "invalid template archive: "+err.Error(), http.StatusBadRequest)
		return
	}
	if requireSet && archive.Set == nil {
		http.Error(w, "archive has no set.json/set document", http.StatusBadRequest)
		return
	}
	response, err := s.applyPortableImport(
		r.Context(), archive, strategy, requireSet, identityFrom(r.Context()).Subject,
	)
	if err != nil {
		var validationErr *templateImportValidationError
		switch {
		case errors.As(err, &validationErr):
			http.Error(w, formatTemplateImportValidationError(validationErr.Result), http.StatusBadRequest)
		case errors.Is(err, errTemplateValidatorUnavailable):
			s.serviceUnavailable(w, "validate template import", err)
		case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrTemplateSetNonExact), errors.Is(err, store.ErrTemplateSetExclusionsUnsupported):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, store.ErrInvalidRef):
			http.Error(w, "archive references template ids unavailable in this catalog", http.StatusBadRequest)
		default:
			s.serverError(w, "import template archive", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func importStrategy(raw string) (string, error) {
	strategy := strings.ToLower(strings.TrimSpace(raw))
	if strategy == "" {
		strategy = "skip"
	}
	switch strategy {
	case "skip", "overwrite", "rename":
		return strategy, nil
	default:
		return "", errors.New("on_conflict must be 'skip', 'overwrite', or 'rename'")
	}
}

func readMultipartFile(w http.ResponseWriter, r *http.Request) ([]byte, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPortableUpload)
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, "", errors.New("multipart form with a 'file' field is required")
	}
	var data []byte
	var filename string
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("read multipart body: %w", err)
		}
		if part.FormName() != "file" {
			_ = part.Close()
			continue
		}
		if data != nil {
			_ = part.Close()
			return nil, "", errors.New("exactly one file is allowed")
		}
		limited := io.LimitReader(part, maxPortableUpload+1)
		data, err = io.ReadAll(limited)
		filename = part.FileName()
		_ = part.Close()
		if err != nil {
			return nil, "", fmt.Errorf("read uploaded file: %w", err)
		}
		if len(data) > maxPortableUpload {
			return nil, "", errors.New("uploaded file exceeds 64 MiB")
		}
	}
	if data == nil || len(data) == 0 {
		return nil, "", errors.New("non-empty 'file' field is required")
	}
	return data, filename, nil
}

func parsePortableArchive(data []byte, filename string) (parsedPortableArchive, error) {
	mediaType := mime.TypeByExtension(strings.ToLower(path.Ext(filename)))
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return parsePortableTarGz(data)
	}
	if mediaType == "application/gzip" {
		return parsedPortableArchive{}, errors.New("file has gzip extension but no gzip header")
	}
	return parsePortableJSON(data)
}

func parsePortableJSON(data []byte) (parsedPortableArchive, error) {
	var doc portableJSONArchive
	dec := json.NewDecoder(io.LimitReader(bytes.NewReader(data), maxPortableExpanded+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return parsedPortableArchive{}, fmt.Errorf("decode JSON: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return parsedPortableArchive{}, err
	}
	if doc.Version != portableArchiveVersion {
		return parsedPortableArchive{}, fmt.Errorf("unsupported version %d", doc.Version)
	}
	return validatePortableEntries(doc.Templates, doc.Set)
}

func parsePortableTarGz(data []byte) (parsedPortableArchive, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return parsedPortableArchive{}, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := make(map[string][]byte)
	var total int64
	count := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return parsedPortableArchive{}, fmt.Errorf("tar: %w", err)
		}
		count++
		if count > maxPortableFiles {
			return parsedPortableArchive{}, fmt.Errorf("archive exceeds %d files", maxPortableFiles)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return parsedPortableArchive{}, fmt.Errorf("unsupported tar entry %q", hdr.Name)
		}
		name := path.Clean(strings.ReplaceAll(hdr.Name, "\\", "/"))
		if name == "." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
			return parsedPortableArchive{}, fmt.Errorf("unsafe tar path %q", hdr.Name)
		}
		if _, duplicate := files[name]; duplicate {
			return parsedPortableArchive{}, fmt.Errorf("duplicate tar entry %q", name)
		}
		if hdr.Size < 0 || total+hdr.Size > maxPortableExpanded {
			return parsedPortableArchive{}, errors.New("archive expands beyond 256 MiB")
		}
		body, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
		if err != nil {
			return parsedPortableArchive{}, fmt.Errorf("read %q: %w", name, err)
		}
		if int64(len(body)) != hdr.Size {
			return parsedPortableArchive{}, fmt.Errorf("short tar entry %q", name)
		}
		total += hdr.Size
		files[name] = body
	}
	// tar.Reader stops at the archive's zero blocks. Drain gzip so its checksum
	// is verified and reject a non-empty appended gzip member instead of silently
	// accepting hidden trailing content outside the manifest.
	trailing, err := io.ReadAll(io.LimitReader(gz, 2))
	if err != nil {
		return parsedPortableArchive{}, fmt.Errorf("gzip checksum: %w", err)
	}
	if len(trailing) != 0 {
		return parsedPortableArchive{}, errors.New("archive has trailing compressed content")
	}
	manifestBody, ok := files["manifest.json"]
	if !ok {
		return parsedPortableArchive{}, errors.New("manifest.json is required")
	}
	delete(files, "manifest.json")
	var manifest portableManifest
	if err := strictJSON(manifestBody, &manifest); err != nil {
		return parsedPortableArchive{}, fmt.Errorf("manifest.json: %w", err)
	}
	if manifest.Version != portableArchiveVersion {
		return parsedPortableArchive{}, fmt.Errorf("unsupported version %d", manifest.Version)
	}
	var set *portableSet
	if setBody, ok := files["set.json"]; ok {
		set = &portableSet{}
		if err := strictJSON(setBody, set); err != nil {
			return parsedPortableArchive{}, fmt.Errorf("set.json: %w", err)
		}
		delete(files, "set.json")
	}
	payloads := make([]portableTemplateJSON, 0, len(manifest.Templates))
	for _, meta := range manifest.Templates {
		name, err := portableTemplatePath(meta.Source, meta.Path)
		if err != nil {
			return parsedPortableArchive{}, err
		}
		body, ok := files[name]
		if !ok {
			return parsedPortableArchive{}, fmt.Errorf("manifest template %q is missing %q", meta.ID, name)
		}
		delete(files, name)
		payloads = append(payloads, portableTemplateJSON{portableTemplateMeta: meta, YAML: string(body)})
	}
	if len(files) > 0 {
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		return parsedPortableArchive{}, fmt.Errorf("unreferenced archive files: %s", strings.Join(names, ", "))
	}
	return validatePortableEntries(payloads, set)
}

func validatePortableEntries(
	payloads []portableTemplateJSON,
	set *portableSet,
) (parsedPortableArchive, error) {
	if len(payloads) > maxPortableFiles {
		return parsedPortableArchive{}, fmt.Errorf("archive exceeds %d templates", maxPortableFiles)
	}
	seen := make(map[string]struct{}, len(payloads))
	for i := range payloads {
		entry := &payloads[i]
		if entry.ID == "" {
			return parsedPortableArchive{}, errors.New("template id is required")
		}
		if entry.Revision <= 0 {
			return parsedPortableArchive{}, fmt.Errorf("template %q revision must be positive", entry.ID)
		}
		if _, duplicate := seen[entry.ID]; duplicate {
			return parsedPortableArchive{}, fmt.Errorf("duplicate template id %q", entry.ID)
		}
		seen[entry.ID] = struct{}{}
		if _, err := portableTemplatePath(entry.Source, entry.Path); err != nil {
			return parsedPortableArchive{}, fmt.Errorf("template %q: %w", entry.ID, err)
		}
		sum := sha256.Sum256([]byte(entry.YAML))
		if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
			return parsedPortableArchive{}, fmt.Errorf("template %q sha256 mismatch", entry.ID)
		}
		var (
			parsedID string
			err      error
		)
		if entry.Source == "custom" {
			var template store.Template
			template, err = customTemplateFromYAML([]byte(entry.YAML))
			parsedID = template.ID
		} else {
			var meta templatespkg.Metadata
			meta, err = templatespkg.Parse(entry.Path, []byte(entry.YAML))
			parsedID = meta.ID
		}
		if err != nil {
			return parsedPortableArchive{}, fmt.Errorf("template %q: %w", entry.ID, err)
		}
		if parsedID != entry.ID {
			return parsedPortableArchive{}, fmt.Errorf(
				"template id %q does not match YAML id %q", entry.ID, parsedID)
		}
	}
	if set != nil {
		set.Name = strings.TrimSpace(set.Name)
		if set.Name == "" {
			return parsedPortableArchive{}, errors.New("set name is required")
		}
		if set.Mode == "" {
			if set.LegacyDynamicAll != nil {
				if *set.LegacyDynamicAll {
					if len(set.ExcludedTemplateIDs) > 0 {
						set.Mode = store.TemplateSetModeExclude
					} else {
						set.Mode = store.TemplateSetModeAll
					}
				} else {
					set.Mode = store.TemplateSetModeExact
				}
			} else {
				set.Mode = store.TemplateSetModeExact
			}
		} else if set.LegacyDynamicAll != nil {
			return parsedPortableArchive{}, errors.New("set must not contain both mode and dynamic_all")
		}
		set.LegacyDynamicAll = nil
		switch set.Mode {
		case store.TemplateSetModeExact, store.TemplateSetModeAll, store.TemplateSetModeExclude:
		default:
			return parsedPortableArchive{}, fmt.Errorf("invalid template set mode %q", set.Mode)
		}
		set.TemplateIDs = uniqueStrings(set.TemplateIDs)
		if set.Mode != store.TemplateSetModeExact && len(set.TemplateIDs) > 0 {
			return parsedPortableArchive{}, errors.New(
				"catalog-derived set must not contain template_ids")
		}
		set.ExcludedTemplateIDs = uniqueStrings(set.ExcludedTemplateIDs)
		if set.Mode != store.TemplateSetModeExclude && len(set.ExcludedTemplateIDs) > 0 {
			return parsedPortableArchive{}, errors.New(
				"only exclude sets may contain excluded_template_ids")
		}
		for _, id := range set.TemplateIDs {
			if _, ok := seen[id]; !ok {
				return parsedPortableArchive{}, fmt.Errorf(
					"set references template %q absent from the archive", id)
			}
		}
	}
	sort.Slice(payloads, func(i, j int) bool { return payloads[i].ID < payloads[j].ID })
	return parsedPortableArchive{Templates: payloads, Set: set}, nil
}

func strictJSON(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return ensureJSONEOF(dec)
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not supported")
		}
		return err
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func missingTemplateIDs(ids []string, templates []store.Template) []string {
	found := make(map[string]struct{}, len(templates))
	for _, template := range templates {
		found[template.ID] = struct{}{}
	}
	var missing []string
	for _, id := range ids {
		if _, ok := found[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}

var downloadNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeDownloadName(name string) string {
	name = strings.Trim(downloadNameChars.ReplaceAllString(name, "-"), "-.")
	if name == "" {
		return "template-set"
	}
	return name
}
