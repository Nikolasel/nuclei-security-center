package store

import (
	"strings"
	"testing"
)

func TestTemplateFilterWhereCombinesFilters(t *testing.T) {
	where, args := templateFilterWhere(TemplateFilter{
		Source:     "upstream",
		Severities: []string{"HIGH"},
		Tags:       []string{"cve", "rce"},
		Query:      "apache",
	})
	for _, fragment := range []string{
		"availability = 'active'",
		"source = $1",
		"lower(severity) = ANY($2)",
		"tags && $3",
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
	if got := templateSortOrder("inserted", ""); got != "created_at DESC, lower(name), id" {
		t.Errorf("inserted order = %q", got)
	}
	if got := templateSortOrder("name", ""); got != "lower(name) ASC, id" {
		t.Errorf("name order = %q", got)
	}
	if got := templateSortOrder("revision", "asc"); got != "revision ASC, lower(name), id" {
		t.Errorf("revision order = %q", got)
	}
	if got := templateSortOrder("source", "desc"); got != "source DESC, lower(name), id" {
		t.Errorf("source order = %q", got)
	}
	if got := templateSortOrder("severity", ""); !strings.Contains(got, "END DESC") {
		t.Errorf("severity order = %q, want severity rank descending", got)
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
