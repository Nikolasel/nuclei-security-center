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

func TestListFindingsRejectsInvalidFilterBeforeDatabase(t *testing.T) {
	_, _, err := (&Store{}).ListFindings(context.Background(), FindingFilter{Query: strings.Repeat("x", 257)})
	if err == nil || !strings.Contains(err.Error(), "query exceeds") {
		t.Fatalf("ListFindings error = %v, want pre-database filter validation error", err)
	}
}
