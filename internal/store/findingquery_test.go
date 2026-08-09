package store

import (
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
