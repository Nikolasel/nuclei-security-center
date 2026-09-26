package store

import (
	"context"
	"strings"
	"testing"
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
