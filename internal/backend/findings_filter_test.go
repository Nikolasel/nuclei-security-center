package backend

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestMultiCSV(t *testing.T) {
	q := url.Values{
		"host":     {"a.example.com", "b,c"}, // repeated + CSV mixed
		"severity": {"critical, high"},       // CSV with spaces
		"tag":      {"rce", "rce", "cve"},    // duplicates de-duped
		"empty":    {"", " , "},              // all-empty → nil
	}
	if got := multiCSV(q, "host"); !reflect.DeepEqual(got, []string{"a.example.com", "b", "c"}) {
		t.Errorf("host = %v", got)
	}
	if got := multiCSV(q, "severity"); !reflect.DeepEqual(got, []string{"critical", "high"}) {
		t.Errorf("severity = %v", got)
	}
	if got := multiCSV(q, "tag"); !reflect.DeepEqual(got, []string{"rce", "cve"}) {
		t.Errorf("tag (deduped) = %v", got)
	}
	if got := multiCSV(q, "empty"); got != nil {
		t.Errorf("empty = %v, want nil", got)
	}
	if got := multiCSV(q, "absent"); got != nil {
		t.Errorf("absent = %v, want nil", got)
	}
}

// The legacy flat params (the pre-condition-builder API) still parse — into a
// single AND-group — so existing bookmarks/API callers keep working.
func TestLegacyFlatQueryBackwardsCompatible(t *testing.T) {
	q := url.Values{"host": {"scanme.sh"}, "state": {"active"}, "severity": {"critical,high"}, "q": {"log4j"}}
	fq, err := findingQueryFromRequest(q)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fq.Groups) != 1 {
		t.Fatalf("want 1 AND-group, got %d", len(fq.Groups))
	}
	got := map[string][]string{}
	for _, c := range fq.Groups[0].Conditions {
		got[c.Field] = c.Values
	}
	if !reflect.DeepEqual(got["host"], []string{"scanme.sh"}) ||
		!reflect.DeepEqual(got["state"], []string{"active"}) ||
		!reflect.DeepEqual(got["severity"], []string{"critical", "high"}) ||
		!reflect.DeepEqual(got["name"], []string{"log4j"}) {
		t.Errorf("legacy flat query mapped wrong: %+v", fq.Groups[0].Conditions)
	}
	if err := store.ValidateFindingQuery(fq); err != nil {
		t.Errorf("legacy query does not validate: %v", err)
	}
}

// The structured `filter` JSON param parses into the condition tree.
func TestFilterJSONParam(t *testing.T) {
	q := url.Values{"filter": {`{"groups":[{"conditions":[{"field":"severity","op":"any_of","values":["critical"]}]}]}`}}
	fq, err := findingQueryFromRequest(q)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fq.Groups) != 1 || len(fq.Groups[0].Conditions) != 1 || fq.Groups[0].Conditions[0].Field != "severity" {
		t.Errorf("filter JSON parsed wrong: %+v", fq)
	}
	// Malformed JSON is a parse error (→ 400 at the handler).
	if _, err := findingQueryFromRequest(url.Values{"filter": {"{bad json"}}); err == nil {
		t.Error("malformed filter JSON accepted")
	}
}
