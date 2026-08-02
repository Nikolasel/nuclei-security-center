package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func portableTestTemplate(id, source, path string) store.Template {
	yaml := "id: " + id + `
info:
  name: Portable example
  author: test
  severity: low
http:
  - method: GET
    path: ["{{BaseURL}}"]
`
	sum := sha256.Sum256([]byte(yaml))
	return store.Template{
		ID: id, Source: source, Path: path, YAML: yaml,
		ContentSHA256: hex.EncodeToString(sum[:]), Revision: 3,
	}
}

func TestPortableTarGzRoundTripPreservesYAMLAndSet(t *testing.T) {
	template := portableTestTemplate("portable-check", "custom", "custom/portable-check.yaml")
	set := &portableSet{Name: "Portable set", TemplateIDs: []string{template.ID}}
	data, err := buildPortableTarGz([]store.Template{template}, set)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parsePortableTarGz(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Templates) != 1 || parsed.Templates[0].YAML != template.YAML {
		t.Fatalf("YAML did not round-trip byte-for-byte: %+v", parsed.Templates)
	}
	if parsed.Set == nil || parsed.Set.Name != set.Name ||
		len(parsed.Set.TemplateIDs) != 1 || parsed.Set.TemplateIDs[0] != template.ID {
		t.Fatalf("set did not round-trip: %+v", parsed.Set)
	}
}

func TestPortableJSONRoundTripPreservesYAML(t *testing.T) {
	template := portableTestTemplate("portable-json", "custom", "custom/portable-json.yaml")
	data, err := buildPortableJSON([]store.Template{template}, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parsePortableJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Templates) != 1 || parsed.Templates[0].YAML != template.YAML {
		t.Fatalf("JSON YAML did not round-trip: %+v", parsed.Templates)
	}
}

func TestPortableExcludeSetRoundTripDoesNotFreezeCatalog(t *testing.T) {
	excluded := portableTestTemplate("noisy-template", "custom", "custom/noisy-template.yaml")
	set := &portableSet{
		Name: "Excluded templates", Mode: store.TemplateSetModeExclude,
		ExcludedTemplateIDs: []string{excluded.ID},
	}
	data, err := buildPortableJSON([]store.Template{excluded}, set)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parsePortableJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Templates) != 1 || parsed.Templates[0].ID != excluded.ID ||
		parsed.Set == nil || parsed.Set.Mode != store.TemplateSetModeExclude || len(parsed.Set.TemplateIDs) != 0 ||
		len(parsed.Set.ExcludedTemplateIDs) != 1 || parsed.Set.ExcludedTemplateIDs[0] != excluded.ID {
		t.Fatalf("exclude set did not round-trip exclusions without freezing membership: %+v", parsed)
	}
}

func TestPortableAllSetRoundTripDoesNotFreezeCatalog(t *testing.T) {
	set := &portableSet{Name: "All templates", Mode: store.TemplateSetModeAll}
	data, err := buildPortableJSON(nil, set)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parsePortableJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Set == nil || parsed.Set.Mode != store.TemplateSetModeAll ||
		len(parsed.Set.TemplateIDs) != 0 || len(parsed.Set.ExcludedTemplateIDs) != 0 {
		t.Fatalf("all set did not round-trip as catalog-derived: %+v", parsed.Set)
	}
}

func TestPortableLegacyDynamicShapeNormalizesToExplicitMode(t *testing.T) {
	legacyAll := true
	set := &portableSet{
		Name: "Legacy exclusions", LegacyDynamicAll: &legacyAll,
		ExcludedTemplateIDs: []string{"noisy"},
	}
	parsed, err := validatePortableEntries(nil, set)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Set.Mode != store.TemplateSetModeExclude || parsed.Set.LegacyDynamicAll != nil {
		t.Fatalf("legacy shape was not normalized: %+v", parsed.Set)
	}
}

func TestPortableCatalogDerivedSetRejectsFrozenMembership(t *testing.T) {
	_, err := validatePortableEntries(nil, &portableSet{
		Name: "Invalid all set", Mode: store.TemplateSetModeAll, TemplateIDs: []string{"one"},
	})
	if err == nil || !strings.Contains(err.Error(), "catalog-derived set must not contain template_ids") {
		t.Fatalf("catalog-derived membership error = %v", err)
	}
}

func TestPortableExactSetRejectsExclusions(t *testing.T) {
	_, err := validatePortableEntries(nil, &portableSet{
		Name: "Invalid exact set", Mode: store.TemplateSetModeExact, ExcludedTemplateIDs: []string{"noisy"},
	})
	if err == nil || !strings.Contains(err.Error(), "only exclude sets may contain excluded_template_ids") {
		t.Fatalf("exact exclusion error = %v", err)
	}
}

func TestPortableExcludeSetMayReferenceExistingExclusion(t *testing.T) {
	if _, err := validatePortableEntries(nil, &portableSet{
		Name: "Excluded templates", Mode: store.TemplateSetModeExclude,
		ExcludedTemplateIDs: []string{"upstream-template"},
	}); err != nil {
		t.Fatalf("exclude reference should be valid without bundled YAML: %v", err)
	}
}

func TestPortableArchiveRejectsHashMismatchAndUnsafePath(t *testing.T) {
	template := portableTestTemplate("bad-hash", "custom", "custom/bad-hash.yaml")
	payload := portableTemplateJSON{
		portableTemplateMeta: portableTemplateMeta{
			ID: template.ID, Source: template.Source, Path: template.Path,
			Revision: template.Revision, SHA256: strings.Repeat("0", 64),
		},
		YAML: template.YAML,
	}
	if _, err := validatePortableEntries([]portableTemplateJSON{payload}, nil); err == nil ||
		!strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("hash mismatch error = %v", err)
	}
	payload.SHA256 = template.ContentSHA256
	payload.Path = "../../escape.yaml"
	if _, err := validatePortableEntries([]portableTemplateJSON{payload}, nil); err == nil ||
		!strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("unsafe path error = %v", err)
	}
}

func TestPortableArchiveRejectsInvalidRevision(t *testing.T) {
	template := portableTestTemplate("bad-revision", "custom", "custom/bad-revision.yaml")
	payload := portableTemplateJSON{
		portableTemplateMeta: portableTemplateMeta{
			ID: template.ID, Source: template.Source, Path: template.Path,
			Revision: 0, SHA256: template.ContentSHA256,
		},
		YAML: template.YAML,
	}
	if _, err := validatePortableEntries([]portableTemplateJSON{payload}, nil); err == nil ||
		!strings.Contains(err.Error(), "revision must be positive") {
		t.Fatalf("revision error = %v", err)
	}
}

func TestPortableSetMustReferenceArchiveTemplates(t *testing.T) {
	template := portableTestTemplate("present", "custom", "custom/present.yaml")
	payload := portableTemplateJSON{
		portableTemplateMeta: portableTemplateMeta{
			ID: template.ID, Source: template.Source, Path: template.Path,
			Revision: template.Revision, SHA256: template.ContentSHA256,
		},
		YAML: template.YAML,
	}
	_, err := validatePortableEntries(
		[]portableTemplateJSON{payload},
		&portableSet{Name: "Broken", TemplateIDs: []string{"missing"}},
	)
	if err == nil || !strings.Contains(err.Error(), "absent from the archive") {
		t.Fatalf("missing member error = %v", err)
	}
}

func TestImportedNamesAreDeterministic(t *testing.T) {
	occupied := map[string]struct{}{
		"check-imported":   {},
		"check-imported-2": {},
	}
	if got := nextImportedTemplateID("check", occupied); got != "check-imported-3" {
		t.Errorf("template id = %q", got)
	}
	sets := []store.TemplateSet{{Name: "Portable"}, {Name: "Portable (imported)"}}
	if got := nextImportedSetName("Portable", sets); got != "Portable (imported 2)" {
		t.Errorf("set name = %q", got)
	}
}

func TestImportStrategy(t *testing.T) {
	for _, valid := range []string{"", "skip", "overwrite", "rename", "RENAME"} {
		if _, err := importStrategy(valid); err != nil {
			t.Errorf("%q rejected: %v", valid, err)
		}
	}
	if _, err := importStrategy("merge"); err == nil {
		t.Fatal("expected invalid strategy rejection")
	}
}
