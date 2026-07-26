package backend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestPlanPortableTemplateWritesValidatesOnlySelectedWrites(t *testing.T) {
	existing := portableEntry(portableTestTemplate(
		"existing", "custom", "custom/existing.yaml",
	))
	created := portableEntry(portableTestTemplate(
		"created", "custom", "custom/created.yaml",
	))
	upstream := portableEntry(portableTestTemplate(
		"upstream", "upstream", "http/upstream.yaml",
	))
	plan, err := planPortableTemplateWrites(
		parsedPortableArchive{Templates: []portableTemplateJSON{existing, created, upstream}},
		"skip",
		map[string]string{"existing": "custom", "upstream": "upstream"},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Writes) != 1 || plan.Writes[0].Template.ID != "created" {
		t.Fatalf("writes = %+v, want only created", plan.Writes)
	}
	if plan.Summary.Created != 1 || plan.Summary.Skipped != 1 || plan.Summary.UpstreamIgnored != 1 {
		t.Fatalf("summary = %+v", plan.Summary)
	}
}

func TestPlanPortableTemplateWritesValidatesRenamedBytes(t *testing.T) {
	entry := portableEntry(portableTestTemplate(
		"collision", "custom", "custom/collision.yaml",
	))
	plan, err := planPortableTemplateWrites(
		parsedPortableArchive{Templates: []portableTemplateJSON{entry}},
		"rename",
		map[string]string{"collision": "custom"},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Writes) != 1 || plan.Writes[0].Template.ID != "collision-imported" {
		t.Fatalf("writes = %+v", plan.Writes)
	}
	if !strings.Contains(plan.Writes[0].Template.YAML, "id: collision-imported") {
		t.Fatalf("renamed YAML was not selected for validation: %q", plan.Writes[0].Template.YAML)
	}
}

func TestValidateThenApplyMixedInvalidSkipsTransaction(t *testing.T) {
	writes := []store.TemplateImportWrite{
		{Template: store.Template{ID: "good"}},
		{Template: store.Template{ID: "bad"}},
	}
	applied := false
	_, _, err := validateThenApplyTemplateImport(
		context.Background(), writes, nil, "operator",
		func(_ context.Context, got []store.TemplateImportWrite) (types.TemplateBatchValidationResult, error) {
			if len(got) != 2 {
				t.Fatalf("validator writes = %d, want 2", len(got))
			}
			return types.TemplateBatchValidationResult{
				Valid: false,
				Failures: []types.TemplateValidationFailure{{
					TemplateID: "bad", Errors: []string{"invalid matcher"},
				}},
				Errors:        []string{},
				NucleiVersion: "v3.11.0",
			}, nil
		},
		func(context.Context, []store.TemplateImportWrite, *store.TemplateSetImportWrite, string) (*store.TemplateSet, error) {
			applied = true
			return nil, nil
		},
	)
	var validationErr *templateImportValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %v, want templateImportValidationError", err)
	}
	if applied {
		t.Fatal("store transaction ran after an invalid mixed batch")
	}
	if !strings.Contains(err.Error(), `template "bad"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateThenApplySuccessReportsVersion(t *testing.T) {
	writes := []store.TemplateImportWrite{{Template: store.Template{ID: "good"}}}
	applied := false
	validation, _, err := validateThenApplyTemplateImport(
		context.Background(), writes, nil, "operator",
		func(context.Context, []store.TemplateImportWrite) (types.TemplateBatchValidationResult, error) {
			return types.TemplateBatchValidationResult{
				Valid: true, Failures: []types.TemplateValidationFailure{},
				Errors: []string{}, NucleiVersion: "v3.11.0",
			}, nil
		},
		func(context.Context, []store.TemplateImportWrite, *store.TemplateSetImportWrite, string) (*store.TemplateSet, error) {
			applied = true
			return nil, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !applied || validation == nil || validation.NucleiVersion != "v3.11.0" {
		t.Fatalf("applied=%v validation=%+v", applied, validation)
	}
}

func TestValidateThenApplyUnavailableSkipsTransaction(t *testing.T) {
	applied := false
	_, _, err := validateThenApplyTemplateImport(
		context.Background(),
		[]store.TemplateImportWrite{{Template: store.Template{ID: "good"}}},
		nil,
		"operator",
		func(context.Context, []store.TemplateImportWrite) (types.TemplateBatchValidationResult, error) {
			return types.TemplateBatchValidationResult{}, errTemplateValidatorUnavailable
		},
		func(context.Context, []store.TemplateImportWrite, *store.TemplateSetImportWrite, string) (*store.TemplateSet, error) {
			applied = true
			return nil, nil
		},
	)
	if !errors.Is(err, errTemplateValidatorUnavailable) {
		t.Fatalf("error = %v, want unavailable", err)
	}
	if applied {
		t.Fatal("store transaction ran while validator was unavailable")
	}
}

func TestValidateThenApplyNoCustomWritesSkipsNuclei(t *testing.T) {
	validated := false
	applied := false
	validation, _, err := validateThenApplyTemplateImport(
		context.Background(), nil, nil, "operator",
		func(context.Context, []store.TemplateImportWrite) (types.TemplateBatchValidationResult, error) {
			validated = true
			return types.TemplateBatchValidationResult{}, nil
		},
		func(context.Context, []store.TemplateImportWrite, *store.TemplateSetImportWrite, string) (*store.TemplateSet, error) {
			applied = true
			return nil, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if validated {
		t.Fatal("Nuclei ran despite no selected custom writes")
	}
	if !applied || validation != nil {
		t.Fatalf("applied=%v validation=%+v", applied, validation)
	}
}

func portableEntry(template store.Template) portableTemplateJSON {
	return portableTemplateJSON{
		portableTemplateMeta: portableTemplateMeta{
			ID: template.ID, Source: template.Source, Path: template.Path,
			Revision: template.Revision, SHA256: template.ContentSHA256,
		},
		YAML: template.YAML,
	}
}
