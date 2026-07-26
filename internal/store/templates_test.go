package store

import (
	"strings"
	"testing"
)

func TestTemplateFilterWhereCVEAndOtherFilters(t *testing.T) {
	where, args := templateFilterWhere(TemplateFilter{
		Source:     "upstream",
		Severities: []string{"HIGH"},
		Tags:       []string{"rce"},
		CVEOnly:    true,
		Query:      "apache",
	})
	for _, fragment := range []string{
		"availability = 'active'",
		"source = $1",
		"lower(severity) = ANY($2)",
		"tags && $3",
		"'cve' = ANY(tags)",
		"id ILIKE $4",
	} {
		if !strings.Contains(where, fragment) {
			t.Errorf("where %q does not contain %q", where, fragment)
		}
	}
	if len(args) != 4 {
		t.Fatalf("args = %#v, want 4 values", args)
	}
}

func TestTemplateSortOrder(t *testing.T) {
	if got := templateSortOrder("inserted"); got != "created_at DESC, lower(name), id" {
		t.Errorf("inserted order = %q", got)
	}
	if got := templateSortOrder("name"); got != "lower(name), id" {
		t.Errorf("name order = %q", got)
	}
}

func TestNullableCountTracksKnownBundleState(t *testing.T) {
	if got := nullableCount("", 0); got != nil {
		t.Fatalf("unknown bundle count = %v, want nil", *got)
	}
	got := nullableCount("digest", 0)
	if got == nil || *got != 0 {
		t.Fatalf("known empty bundle count = %v, want 0", got)
	}
}
