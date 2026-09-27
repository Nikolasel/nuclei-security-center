package backend

import (
	"net/url"
	"reflect"
	"strings"
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

// matched_at and type are allowlisted for both the structured filter and the
// legacy flat params. List and export both call findingQueryFromRequest, so a
// matched_at filter narrows them identically. Unknown fields and operators
// still fail validation (the handlers map that to HTTP 400).
func TestMatchedAtAndTypeFilterSharedByListAndExport(t *testing.T) {
	legacy, err := findingQueryFromRequest(url.Values{
		"matched_at": {"https://host/admin"},
		"type":       {"http,DNS"},
	})
	if err != nil {
		t.Fatalf("legacy parse: %v", err)
	}
	if err := store.ValidateFindingQuery(legacy); err != nil {
		t.Fatalf("legacy matched_at/type query: %v", err)
	}
	got := map[string]store.FindingCondition{}
	if len(legacy.Groups) != 1 {
		t.Fatalf("want 1 AND-group, got %d", len(legacy.Groups))
	}
	for _, c := range legacy.Groups[0].Conditions {
		got[c.Field] = c
	}
	if got["matched_at"].Op != "contains" || !reflect.DeepEqual(got["matched_at"].Values, []string{"https://host/admin"}) {
		t.Fatalf("legacy matched_at = %+v", got["matched_at"])
	}
	if got["type"].Op != "any_of" || !reflect.DeepEqual(got["type"].Values, []string{"http", "DNS"}) {
		t.Fatalf("legacy type = %+v", got["type"])
	}

	structured, err := findingQueryFromRequest(url.Values{"filter": {`{"groups":[{"conditions":[
		{"field":"matched_at","op":"contains","values":["/admin"]},
		{"field":"type","op":"any_of","values":["http"]}
	]}]}`}})
	if err != nil {
		t.Fatalf("structured parse: %v", err)
	}
	if err := store.ValidateFindingQuery(structured); err != nil {
		t.Fatalf("structured matched_at/type query: %v", err)
	}

	unknownField, err := findingQueryFromRequest(url.Values{"filter": {`{"groups":[{"conditions":[{"field":"nope","op":"any_of","values":["x"]}]}]}`}})
	if err != nil {
		t.Fatalf("unknown field should parse before validation: %v", err)
	}
	if err := store.ValidateFindingQuery(unknownField); err == nil || !strings.Contains(err.Error(), "unknown filter field") {
		t.Fatalf("unknown field error = %v", err)
	}
	badOp, err := findingQueryFromRequest(url.Values{"filter": {`{"groups":[{"conditions":[{"field":"type","op":"contains","values":["http"]}]}]}`}})
	if err != nil {
		t.Fatalf("bad operator should parse before validation: %v", err)
	}
	if err := store.ValidateFindingQuery(badOp); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("bad operator error = %v", err)
	}
}

func TestFilterJSONParamRejectsOversizedFilter(t *testing.T) {
	raw := `{"groups":[{"conditions":[{"field":"host","op":"contains","values":["` +
		strings.Repeat("x", 70<<10) + `"]}]}]}`
	if _, err := findingQueryFromRequest(url.Values{"filter": {raw}}); err == nil || !strings.Contains(err.Error(), "filter exceeds") {
		t.Fatalf("findingQueryFromRequest error = %v, want oversized-filter error", err)
	}
}

func TestFindingFilterQueryParamsRejectsOversizedLegacyFilter(t *testing.T) {
	q := url.Values{"host": {strings.Repeat("x", maxFindingFilterBytes+1)}}
	if err := validateFindingFilterQueryParams(q); err == nil || !strings.Contains(err.Error(), "filter exceeds") {
		t.Fatalf("validateFindingFilterQueryParams error = %v, want oversized-filter error", err)
	}
}

func TestFindingFilterQueryParamsRejectsDuplicateStructuredFilters(t *testing.T) {
	q := url.Values{"filter": {`{}`, `{}`}}
	if err := validateFindingFilterQueryParams(q); err == nil || !strings.Contains(err.Error(), "one filter") {
		t.Fatalf("validateFindingFilterQueryParams error = %v, want duplicate-filter error", err)
	}
}
