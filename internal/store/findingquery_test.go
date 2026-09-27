package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestValidateFindingQueryRejectsTooManyValues(t *testing.T) {
	values := make([]string, 101)
	for i := range values {
		values[i] = "high"
	}

	err := ValidateFindingQuery(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
		Field: "severity", Op: "any_of", Values: values,
	}}}}})
	if err == nil || !strings.Contains(err.Error(), "too many filter values") {
		t.Fatalf("ValidateFindingQuery error = %v, want too-many-values error", err)
	}
}

func TestValidateFindingQueryRejectsOversizedValue(t *testing.T) {
	err := ValidateFindingQuery(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
		Field: "host", Op: "contains", Values: []string{strings.Repeat("x", 257)},
	}}}}})
	if err == nil || !strings.Contains(err.Error(), "filter value exceeds") {
		t.Fatalf("ValidateFindingQuery error = %v, want oversized-value error", err)
	}
}

func TestValidateFindingQueryBoundsValuesForValueFreeOperators(t *testing.T) {
	values := make([]string, 101)
	for i := range values {
		values[i] = "ignored"
	}

	err := ValidateFindingQuery(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
		Field: "host", Op: "is_empty", Values: values,
	}}}}})
	if err == nil || !strings.Contains(err.Error(), "too many filter values") {
		t.Fatalf("ValidateFindingQuery error = %v, want too-many-values error", err)
	}
}

func TestValidateFindingQueryAcceptsValuesAtLimits(t *testing.T) {
	values := make([]string, 100)
	for i := range values {
		values[i] = strings.Repeat("x", 256)
	}

	if err := ValidateFindingQuery(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
		Field: "host", Op: "contains", Values: values,
	}}}}}); err != nil {
		t.Fatalf("ValidateFindingQuery at value limits = %v, want nil", err)
	}

	if err := ValidateFindingQuery(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "matcher", Op: "contains", Values: []string{"tls13"}},
		{Field: "extracted_result", Op: "contains", Values: []string{"tls12"}},
	}}}}); err != nil {
		t.Fatalf("ValidateFindingQuery result identity = %v, want nil", err)
	}
	err := ValidateFindingQuery(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{
		Field: "extracted_result", Op: "starts_with", Values: []string{"tls"},
	}}}}})
	if err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("ValidateFindingQuery extracted_result starts_with = %v, want operator error", err)
	}
}

func TestValidateFindingFilterBoundsOccurrenceFilters(t *testing.T) {
	tooManySeverities := make([]string, 101)
	for i := range tooManySeverities {
		tooManySeverities[i] = "high"
	}

	cases := []struct {
		name  string
		input FindingFilter
		want  string
	}{
		{name: "query", input: FindingFilter{Query: strings.Repeat("x", 257)}, want: "query exceeds"},
		{name: "host", input: FindingFilter{Host: strings.Repeat("x", 257)}, want: "host exceeds"},
		{name: "cve", input: FindingFilter{CVE: strings.Repeat("x", 257)}, want: "cve exceeds"},
		{name: "tag", input: FindingFilter{Tag: strings.Repeat("x", 257)}, want: "tag exceeds"},
		{name: "severity count", input: FindingFilter{Severities: tooManySeverities}, want: "too many filter values"},
		{name: "severity value", input: FindingFilter{Severities: []string{strings.Repeat("x", 257)}}, want: "filter value exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFindingFilter(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateFindingFilter error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildFindingWhereMatchedAtAndType(t *testing.T) {
	var args []any
	where, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "matched_at", Op: "contains", Values: []string{"https://host/admin"}},
		{Field: "type", Op: "any_of", Values: []string{"HTTP", "dns"}},
	}}}}, &args)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(where, "l.matched_at ILIKE ANY($1)") {
		t.Fatalf("matched_at SQL = %s", where)
	}
	if !strings.Contains(where, "lower(l.type) = ANY($2)") {
		t.Fatalf("type SQL = %s", where)
	}
	patterns, ok := args[0].([]string)
	if !ok || len(patterns) != 1 || patterns[0] != "%https://host/admin%" {
		t.Fatalf("matched_at pattern = %#v", args[0])
	}
	protocols, ok := args[1].([]string)
	if !ok || len(protocols) != 2 || protocols[0] != "http" || protocols[1] != "dns" {
		t.Fatalf("type values = %#v, want lowercased http, dns", args[1])
	}

	rejected := []FindingCondition{
		{Field: "matched_at", Op: "any_of", Values: []string{"https://host/admin"}},
		{Field: "type", Op: "contains", Values: []string{"http"}},
		{Field: "not_a_field", Op: "any_of", Values: []string{"x"}},
	}
	for _, cond := range rejected {
		var bound []any
		_, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{cond}}}}, &bound)
		if err == nil {
			t.Fatalf("condition %+v compiled, want validation error", cond)
		}
	}
}

func TestListFindingsRejectsInvalidFilterBeforeDatabase(t *testing.T) {
	_, _, err := (&Store{}).ListFindings(context.Background(), FindingFilter{Query: strings.Repeat("x", 257)})
	if err == nil || !strings.Contains(err.Error(), "query exceeds") {
		t.Fatalf("ListFindings error = %v, want pre-database filter validation error", err)
	}
}

func TestBuildFindingWhereTimeRangeAndNameNegation(t *testing.T) {
	var args []any
	where, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "state", Op: "any_of", Values: []string{"new", "active", "resurfaced"}},
		{Field: "first_seen_at", Op: "after", Values: []string{"2026-01-01"}},
		{Field: "name", Op: "not_contains", Values: []string{"log4j"}},
	}}}}, &args)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(where, "l.first_seen_at >= $") {
		t.Fatalf("first_seen_at SQL = %s", where)
	}
	if !strings.Contains(where, "NOT (") || !strings.Contains(where, "l.name ILIKE ANY($") {
		t.Fatalf("name not_contains SQL = %s", where)
	}
	if _, ok := args[1].(time.Time); !ok {
		t.Fatalf("first_seen_at bound = %#v, want time.Time", args[1])
	}

	afterRFC, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "last_seen_at", Op: "before", Values: []string{"2026-01-15T12:00:00Z"}},
	}}}}, &[]any{})
	if err != nil {
		t.Fatalf("rfc3339 before: %v", err)
	}
	if !strings.Contains(afterRFC, "l.last_seen_at <= $1") {
		t.Fatalf("rfc3339 before SQL = %s", afterRFC)
	}

	var betweenArgs []any
	between, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "first_seen_at", Op: "between", Values: []string{"2026-01-01", "2026-01-07"}},
	}}}}, &betweenArgs)
	if err != nil {
		t.Fatalf("between: %v", err)
	}
	if !strings.Contains(between, "l.first_seen_at >= $1 AND l.first_seen_at < $2") {
		t.Fatalf("date-only between SQL = %s", between)
	}
	lo, ok := betweenArgs[0].(time.Time)
	if !ok || !lo.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("between lo = %#v", betweenArgs[0])
	}
	hi, ok := betweenArgs[1].(time.Time)
	if !ok || !hi.Equal(time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("between exclusive hi = %#v", betweenArgs[1])
	}

	rejected := []FindingCondition{
		{Field: "first_seen_at", Op: "contains", Values: []string{"2026-01-01"}},
		{Field: "first_seen_at", Op: "after", Values: []string{"not-a-date"}},
		{Field: "first_seen_at", Op: "between", Values: []string{"2026-02-01", "2026-01-01"}},
		{Field: "name", Op: "after", Values: []string{"2026-01-01"}},
		{Field: "severity", Op: "before", Values: []string{"2026-01-01"}},
	}
	for _, cond := range rejected {
		var bound []any
		_, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{cond}}}}, &bound)
		if err == nil {
			t.Fatalf("condition %+v compiled, want validation error", cond)
		}
	}
}

func TestValidateFindingSort(t *testing.T) {
	if err := ValidateFindingSort("", ""); err != nil {
		t.Fatalf("default sort: %v", err)
	}
	if err := ValidateFindingSort("first_seen_at", "desc"); err != nil {
		t.Fatalf("allowlisted sort: %v", err)
	}
	if err := ValidateFindingSort("bogus", "asc"); err == nil {
		t.Fatal("unknown sort field accepted")
	}
	if err := ValidateFindingSort("severity", "sideways"); err == nil {
		t.Fatal("bad order accepted")
	}
	if err := ValidateFindingSort("", "desc"); err == nil {
		t.Fatal("order without sort accepted")
	}
}

func TestLifecycleOrderBy(t *testing.T) {
	got, err := lifecycleOrderBy(FindingQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if got != lcDefaultOrderBy {
		t.Fatalf("default order = %q", got)
	}
	got, err = lifecycleOrderBy(FindingQuery{Sort: "first_seen_at", Order: "asc"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "l.first_seen_at ASC") || !strings.Contains(got, "l.id DESC") {
		t.Fatalf("first_seen_at order = %q", got)
	}
	got, err = lifecycleOrderBy(FindingQuery{Sort: "severity"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, strings.ToUpper(defaultFindingSortOrder("severity"))) {
		t.Fatalf("severity default direction missing: %q", got)
	}
	if _, err := lifecycleOrderBy(FindingQuery{Sort: "not_a_column"}); err == nil {
		t.Fatal("unknown sort compiled")
	}
}
