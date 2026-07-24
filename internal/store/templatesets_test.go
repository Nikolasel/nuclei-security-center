package store

import (
	"reflect"
	"strings"
	"testing"
)

func TestLegacyTemplateFilterWhereEmptyMatchesActiveCatalog(t *testing.T) {
	where, args := legacyTemplateFilterWhere(LegacyTemplateFilter{})
	if where != "availability = 'active' AND source = 'upstream'" {
		t.Fatalf("where = %q", where)
	}
	if len(args) != 0 {
		t.Fatalf("args = %v, want none", args)
	}
}

func TestLegacyTemplateFilterWhereCombinesDimensions(t *testing.T) {
	filter := LegacyTemplateFilter{
		GitRef:     "v9.6.3", // historical context only; the current catalog is resolved.
		Severities: []string{"Critical", "HIGH"},
		Tags:       []string{"cve", "rce"},
		Paths:      []string{"http/cves/", "network/check.yaml"},
	}
	where, args := legacyTemplateFilterWhere(filter)

	for _, want := range []string{
		"availability = 'active'",
		"source = 'upstream'",
		"lower(severity) = ANY($1)",
		"tags && $2",
		"path = ANY($3)",
		"starts_with(path, selected.prefix || '/')",
	} {
		if !strings.Contains(where, want) {
			t.Errorf("where %q does not contain %q", where, want)
		}
	}
	wantArgs := []any{
		[]string{"critical", "high"},
		[]string{"cve", "rce"},
		[]string{"http/cves", "network/check.yaml"},
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v, want %#v", args, wantArgs)
	}
	if strings.Contains(where, "v9.6.3") {
		t.Errorf("retired per-set git ref leaked into catalog predicate: %q", where)
	}
	if strings.Contains(where, "LIKE") {
		t.Errorf("path predicate uses wildcard matching: %q", where)
	}
}
