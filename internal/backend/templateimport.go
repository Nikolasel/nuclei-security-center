package backend

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	templatespkg "github.com/Nikolasel/nuclei-security-center/internal/templates"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

type portableTemplateWritePlan struct {
	Writes   []store.TemplateImportWrite
	Renamed  map[string]string
	Occupied map[string]struct{}
	Summary  templateImportSummary
}

func (s *Server) applyPortableImport(
	ctx context.Context,
	archive parsedPortableArchive,
	strategy string,
	requireSet bool,
	actor string,
) (portableImportResponse, error) {
	sources, err := s.store.TemplateSources(ctx)
	if err != nil {
		return portableImportResponse{}, err
	}
	plan, err := planPortableTemplateWrites(archive, strategy, sources, requireSet)
	if err != nil {
		return portableImportResponse{}, err
	}
	writes := plan.Writes
	renamed := plan.Renamed
	occupied := plan.Occupied
	response := portableImportResponse{Templates: plan.Summary}

	var (
		setWrite    *store.TemplateSetImportWrite
		existingSet *store.TemplateSet
	)
	if requireSet {
		setDoc := archive.Set
		memberIDs := make([]string, 0, len(setDoc.TemplateIDs))
		for _, originalID := range setDoc.TemplateIDs {
			id := originalID
			if replacement := renamed[originalID]; replacement != "" {
				id = replacement
			}
			if _, ok := occupied[id]; !ok {
				return portableImportResponse{}, fmt.Errorf(
					"%w: template %q is not present in the destination catalog",
					store.ErrInvalidRef, id,
				)
			}
			memberIDs = append(memberIDs, id)
		}
		memberIDs = uniqueStrings(memberIDs)

		sets, err := s.store.ListTemplateSets(ctx)
		if err != nil {
			return portableImportResponse{}, err
		}
		name := setDoc.Name
		for i := range sets {
			if strings.EqualFold(sets[i].Name, name) {
				existingSet = &sets[i]
				break
			}
		}
		switch {
		case existingSet == nil:
			setWrite = &store.TemplateSetImportWrite{Name: name, TemplateIDs: memberIDs}
			response.SetStatus = "created"
		case strategy == "skip":
			response.Set = existingSet
			response.SetStatus = "skipped"
		case strategy == "overwrite":
			setWrite = &store.TemplateSetImportWrite{
				ExistingID: existingSet.ID, Name: existingSet.Name, TemplateIDs: memberIDs,
			}
			response.SetStatus = "updated"
		case strategy == "rename":
			name = nextImportedSetName(name, sets)
			setWrite = &store.TemplateSetImportWrite{Name: name, TemplateIDs: memberIDs}
			response.SetStatus = "renamed"
		}
	}

	validation, importedSet, err := validateThenApplyTemplateImport(
		ctx, writes, setWrite, actor,
		s.validateTemplateImportWrites,
		s.store.ApplyTemplateImport,
	)
	if err != nil {
		return portableImportResponse{}, err
	}
	response.Validation = validation
	if importedSet != nil {
		response.Set = importedSet
	}
	sort.Slice(response.Templates.Renamed, func(i, j int) bool {
		return response.Templates.Renamed[i].From < response.Templates.Renamed[j].From
	})
	return response, nil
}

func planPortableTemplateWrites(
	archive parsedPortableArchive,
	strategy string,
	sources map[string]string,
	requireSet bool,
) (portableTemplateWritePlan, error) {
	occupied := make(map[string]struct{}, len(sources)+len(archive.Templates))
	for id := range sources {
		occupied[id] = struct{}{}
	}
	renamed := make(map[string]string)
	var writes []store.TemplateImportWrite
	summary := templateImportSummary{Renamed: []importRename{}}

	for _, entry := range archive.Templates {
		if entry.Source == "upstream" {
			summary.UpstreamIgnored++
			continue
		}
		template, err := customTemplateFromYAML([]byte(entry.YAML))
		if err != nil {
			return portableTemplateWritePlan{}, err
		}
		existingSource, exists := sources[entry.ID]
		if !exists {
			writes = append(writes, store.TemplateImportWrite{Template: template})
			occupied[entry.ID] = struct{}{}
			summary.Created++
			continue
		}
		if existingSource == "upstream" && requireSet && strategy != "rename" {
			return portableTemplateWritePlan{}, fmt.Errorf(
				"%w: custom template %q collides with an upstream template; use on_conflict=rename",
				store.ErrConflict, entry.ID,
			)
		}

		switch strategy {
		case "skip":
			summary.Skipped++
		case "overwrite":
			if existingSource == "upstream" {
				summary.Skipped++
				continue
			}
			writes = append(writes, store.TemplateImportWrite{Template: template, Overwrite: true})
			summary.Updated++
		case "rename":
			newID := nextImportedTemplateID(entry.ID, occupied)
			rewritten, err := templatespkg.RewriteID([]byte(entry.YAML), newID)
			if err != nil {
				return portableTemplateWritePlan{}, fmt.Errorf("rename template %q: %w", entry.ID, err)
			}
			template, err = customTemplateFromYAML(rewritten)
			if err != nil {
				return portableTemplateWritePlan{}, fmt.Errorf("validate renamed template %q: %w", entry.ID, err)
			}
			writes = append(writes, store.TemplateImportWrite{Template: template})
			occupied[newID] = struct{}{}
			renamed[entry.ID] = newID
			summary.Created++
			summary.Renamed = append(summary.Renamed, importRename{
				From: entry.ID, To: newID,
			})
		}
	}
	return portableTemplateWritePlan{
		Writes: writes, Renamed: renamed, Occupied: occupied, Summary: summary,
	}, nil
}

func (s *Server) validateTemplateImportWrites(
	ctx context.Context,
	writes []store.TemplateImportWrite,
) (types.TemplateBatchValidationResult, error) {
	if s.templateBatchValidator == nil {
		return types.TemplateBatchValidationResult{}, errTemplateValidatorUnavailable
	}
	validationCtx, cancel := context.WithTimeout(ctx, types.TemplateBatchValidationRequestTimeout)
	defer cancel()
	return s.templateBatchValidator(validationCtx, writes)
}

type templateImportValidationError struct {
	Result types.TemplateBatchValidationResult
}

func (e *templateImportValidationError) Error() string {
	return formatTemplateImportValidationError(e.Result)
}

type templateImportValidator func(
	context.Context, []store.TemplateImportWrite,
) (types.TemplateBatchValidationResult, error)

type templateImportApplier func(
	context.Context, []store.TemplateImportWrite, *store.TemplateSetImportWrite, string,
) (*store.TemplateSet, error)

func validateThenApplyTemplateImport(
	ctx context.Context,
	writes []store.TemplateImportWrite,
	setWrite *store.TemplateSetImportWrite,
	actor string,
	validate templateImportValidator,
	apply templateImportApplier,
) (*types.TemplateBatchValidationResult, *store.TemplateSet, error) {
	var validation *types.TemplateBatchValidationResult
	if len(writes) > 0 {
		result, err := validate(ctx, writes)
		if err != nil {
			return nil, nil, err
		}
		if !result.Valid {
			return nil, nil, &templateImportValidationError{Result: result}
		}
		validation = &result
	}
	importedSet, err := apply(ctx, writes, setWrite, actor)
	return validation, importedSet, err
}

func formatTemplateImportValidationError(result types.TemplateBatchValidationResult) string {
	parts := make([]string, 0, len(result.Failures)+len(result.Errors)+1)
	version := result.NucleiVersion
	if version == "" {
		version = "unknown version"
	}
	for _, failure := range result.Failures {
		parts = append(parts, fmt.Sprintf(
			"template %q: %s", failure.TemplateID, strings.Join(failure.Errors, "; "),
		))
	}
	parts = append(parts, result.Errors...)
	if result.Truncated {
		parts = append(parts, "additional Nuclei diagnostics were truncated")
	}
	if len(parts) == 0 {
		parts = append(parts, "Nuclei rejected the template batch")
	}
	return fmt.Sprintf("nuclei %s import validation failed: %s", version, strings.Join(parts, "; "))
}

func nextImportedTemplateID(base string, occupied map[string]struct{}) string {
	for n := 1; ; n++ {
		suffix := "-imported"
		if n > 1 {
			suffix = fmt.Sprintf("-imported-%d", n)
		}
		prefix := base
		if len(prefix)+len(suffix) > 200 {
			prefix = prefix[:200-len(suffix)]
		}
		candidate := prefix + suffix
		if _, exists := occupied[candidate]; !exists {
			return candidate
		}
	}
}

func nextImportedSetName(base string, sets []store.TemplateSet) string {
	occupied := make(map[string]struct{}, len(sets))
	for _, set := range sets {
		occupied[strings.ToLower(set.Name)] = struct{}{}
	}
	for n := 1; ; n++ {
		suffix := " (imported)"
		if n > 1 {
			suffix = fmt.Sprintf(" (imported %d)", n)
		}
		candidate := base + suffix
		if _, exists := occupied[strings.ToLower(candidate)]; !exists {
			return candidate
		}
	}
}
