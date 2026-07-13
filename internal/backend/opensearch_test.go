package backend

import (
	"encoding/json"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// findTerm walks the built query's bool.filter for a {"term": {field: value}}.
func hasTerm(t *testing.T, q map[string]any, field, want string) bool {
	t.Helper()
	boolQ, ok := q["query"].(map[string]any)["bool"].(map[string]any)
	if !ok {
		return false
	}
	filters, _ := boolQ["filter"].([]any)
	for _, f := range filters {
		fm, _ := f.(map[string]any)
		term, ok := fm["term"].(map[string]any)
		if !ok {
			continue
		}
		if v, ok := term[field]; ok {
			return v == want
		}
	}
	return false
}

func TestBuildLifecycleQueryFacets(t *testing.T) {
	q := buildLifecycleQuery(store.LifecycleFilter{
		TargetID:    "t1",
		Disposition: "accepted",
		State:       "active",
		Tag:         "prod",
		Limit:       25,
		Offset:      50,
	})
	if q["from"] != 50 || q["size"] != 25 {
		t.Errorf("paging: from=%v size=%v", q["from"], q["size"])
	}
	if q["track_total_hits"] != true {
		t.Error("track_total_hits should be true so total is exact")
	}
	for field, want := range map[string]string{
		"target_id":       "t1",
		"disposition":     "accepted",
		"effective_state": "active",
		"tags":            "prod",
	} {
		if !hasTerm(t, q, field, want) {
			t.Errorf("expected term filter %s=%s in %v", field, want, q["query"])
		}
	}
}

func TestBuildLifecycleQueryEmptyIsMatchAll(t *testing.T) {
	q := buildLifecycleQuery(store.LifecycleFilter{})
	if _, ok := q["query"].(map[string]any)["match_all"]; !ok {
		t.Errorf("no filters should produce match_all, got %v", q["query"])
	}
	// Defaults applied.
	if q["size"] != 50 || q["from"] != 0 {
		t.Errorf("defaults: size=%v from=%v", q["size"], q["from"])
	}
}

func TestBuildLifecycleQuerySeverityAndSubstring(t *testing.T) {
	q := buildLifecycleQuery(store.LifecycleFilter{
		Severities: []string{"Critical", "HIGH"},
		Host:       "Example",
		Query:      "log4j",
	})
	body, _ := json.Marshal(q)
	s := string(body)
	// Severities lowercased into a terms filter on effective_severity.
	if !contains(s, `"effective_severity":["critical","high"]`) {
		t.Errorf("severities not lowercased into terms: %s", s)
	}
	// Host substring lowercased into a wildcard.
	if !contains(s, `"host":"*example*"`) {
		t.Errorf("host wildcard missing/uncased: %s", s)
	}
	// Free-text query becomes a match on name OR wildcard on template_id.
	if !contains(s, `"name":"log4j"`) {
		t.Errorf("query match on name missing: %s", s)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// A LifecycleRow must round-trip through JSON so an indexed _source document
// deserializes back into the same row the API returns.
func TestLifecycleRowJSONRoundTrip(t *testing.T) {
	in := store.LifecycleRow{
		ID: 7, TemplateID: "cve-2021-44228", Name: "Log4j", Severity: "critical",
		EffectiveSeverity: "high", Host: "10.0.0.1", CVE: []string{"CVE-2021-44228"},
		Tags: []string{"rce"}, Disposition: "accepted", DetectionState: "active",
		EffectiveState: "accepted", TimesMitigated: 2,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out store.LifecycleRow
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != in.ID || out.EffectiveSeverity != in.EffectiveSeverity || out.EffectiveState != in.EffectiveState {
		t.Errorf("round-trip mismatch: %+v vs %+v", out, in)
	}
}
