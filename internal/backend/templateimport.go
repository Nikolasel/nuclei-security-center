package backend

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	templatespkg "github.com/Nikolasel/nuclei-security-center/internal/templates"
)

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
	occupied := make(map[string]struct{}, len(sources)+len(archive.Templates))
	for id := range sources {
		occupied[id] = struct{}{}
	}
	renamed := make(map[string]string)
	var writes []store.TemplateImportWrite
	response := portableImportResponse{
		Templates: templateImportSummary{Renamed: []importRename{}},
	}

	for _, entry := range archive.Templates {
		if entry.Source == "upstream" {
			response.Templates.UpstreamIgnored++
			continue
		}
		template, err := customTemplateFromYAML([]byte(entry.YAML))
		if err != nil {
			return portableImportResponse{}, err
		}
		existingSource, exists := sources[entry.ID]
		if !exists {
			writes = append(writes, store.TemplateImportWrite{Template: template})
			occupied[entry.ID] = struct{}{}
			response.Templates.Created++
			continue
		}
		if existingSource == "upstream" && requireSet && strategy != "rename" {
			return portableImportResponse{}, fmt.Errorf(
				"%w: custom template %q collides with an upstream template; use on_conflict=rename",
				store.ErrConflict, entry.ID,
			)
		}

		switch strategy {
		case "skip":
			response.Templates.Skipped++
		case "overwrite":
			if existingSource == "upstream" {
				response.Templates.Skipped++
				continue
			}
			writes = append(writes, store.TemplateImportWrite{Template: template, Overwrite: true})
			response.Templates.Updated++
		case "rename":
			newID := nextImportedTemplateID(entry.ID, occupied)
			rewritten, err := templatespkg.RewriteID([]byte(entry.YAML), newID)
			if err != nil {
				return portableImportResponse{}, fmt.Errorf("rename template %q: %w", entry.ID, err)
			}
			template, err = customTemplateFromYAML(rewritten)
			if err != nil {
				return portableImportResponse{}, fmt.Errorf("validate renamed template %q: %w", entry.ID, err)
			}
			writes = append(writes, store.TemplateImportWrite{Template: template})
			occupied[newID] = struct{}{}
			renamed[entry.ID] = newID
			response.Templates.Created++
			response.Templates.Renamed = append(response.Templates.Renamed, importRename{
				From: entry.ID, To: newID,
			})
		}
	}

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

	importedSet, err := s.store.ApplyTemplateImport(ctx, writes, setWrite, actor)
	if err != nil {
		return portableImportResponse{}, err
	}
	if importedSet != nil {
		response.Set = importedSet
	}
	sort.Slice(response.Templates.Renamed, func(i, j int) bool {
		return response.Templates.Renamed[i].From < response.Templates.Renamed[j].From
	})
	return response, nil
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
