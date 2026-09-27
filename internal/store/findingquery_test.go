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

	emptyName, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "name", Op: "is_empty"},
	}}}}, &[]any{})
	if err != nil {
		t.Fatalf("name is_empty: %v", err)
	}
	if !strings.Contains(emptyName, "(l.name IS NULL OR l.name = '')") {
		t.Fatalf("name is_empty SQL = %s", emptyName)
	}
	if strings.Contains(emptyName, "l.template_id") {
		t.Fatalf("name is_empty must not require template_id: %s", emptyName)
	}
	notEmptyName, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "name", Op: "is_not_empty"},
	}}}}, &[]any{})
	if err != nil {
		t.Fatalf("name is_not_empty: %v", err)
	}
	if !strings.Contains(notEmptyName, "(l.name IS NOT NULL AND l.name <> '')") {
		t.Fatalf("name is_not_empty SQL = %s", notEmptyName)
	}
	if strings.Contains(notEmptyName, "l.template_id") {
		t.Fatalf("name is_not_empty must not treat template_id as a name: %s", notEmptyName)
	}
	if !strings.Contains(where, "l.template_id ILIKE ANY($") {
		t.Fatalf("name not_contains must still search template_id: %s", where)
	}

	rejected := []FindingCondition{
		{Field: "first_seen_at", Op: "contains", Values: []string{"2026-01-01"}},
		{Field: "first_seen_at", Op: "after", Values: []string{"not-a-date"}},
		{Field: "first_seen_at", Op: "after", Values: []string{"2026-01-01", "2026-01-07"}},
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
	if err := ValidateFindingSort("host", "asc"); err != nil {
		t.Fatalf("host sort: %v", err)
	}
	if err := ValidateFindingSort("state", "asc"); err != nil {
		t.Fatalf("state sort: %v", err)
	}
	if err := ValidateFindingSort("matcher_name", "asc"); err != nil {
		t.Fatalf("matcher_name sort: %v", err)
	}
	if CanonicalFindingSortField("effective_state") != "state" {
		t.Fatal("effective_state alias")
	}
	if CanonicalFindingSortField("matcher") != "matcher_name" {
		t.Fatal("matcher alias")
	}
	if err := ValidateFindingSort("detection_state", "desc"); err != nil {
		t.Fatalf("detection_state sort: %v", err)
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
	got, err = lifecycleOrderBy(FindingQuery{Sort: "state", Order: "asc"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, findingSortColumns["state"]) || !strings.Contains(got, "ASC") {
		t.Fatalf("state order = %q", got)
	}
	got, err = lifecycleOrderBy(FindingQuery{Sort: "host", Order: "asc"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "l.host ASC") {
		t.Fatalf("host order = %q", got)
	}
	got, err = lifecycleOrderBy(FindingQuery{Sort: "matcher_name", Order: "desc"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "l.matcher_name DESC") {
		t.Fatalf("matcher_name order = %q", got)
	}
	if _, err := lifecycleOrderBy(FindingQuery{Sort: "not_a_column"}); err == nil {
		t.Fatal("unknown sort compiled")
	}
}

func TestBuildFindingWhereTriageOverlayFields(t *testing.T) {
	var args []any
	where, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "disposition", Op: "any_of", Values: []string{"accepted"}},
		{Field: "accept_expires_at", Op: "between", Values: []string{"2026-09-27", "2026-10-04"}},
		{Field: "recast_severity", Op: "any_of", Values: []string{"Low"}},
		{Field: "observed_severity", Op: "any_of", Values: []string{"Critical"}},
		{Field: "times_mitigated", Op: "gte", Values: []string{"1"}},
		{Field: "occurrence_count", Op: "gt", Values: []string{"1"}},
		{Field: "auto_mitigation_eligible", Op: "is", Values: []string{"false"}},
	}}}}, &args)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, want := range []string{
		"l.accept_expires_at >= $",
		"l.accept_expires_at < $",
		"lower(l.recast_severity) = ANY($",
		"lower(l.severity) = ANY($",
		"l.times_mitigated >= $",
		"SELECT COUNT(*) FROM findings occurrence WHERE occurrence.finding_id = l.id) > $",
		"(l.endpoint_key <> '') = $",
	} {
		if !strings.Contains(where, want) {
			t.Fatalf("where missing %q:\n%s", want, where)
		}
	}
	if _, ok := args[1].(time.Time); !ok {
		t.Fatalf("accept_expires_at lo = %#v, want time.Time", args[1])
	}
	if recast, ok := args[3].([]string); !ok || recast[0] != "low" {
		t.Fatalf("recast_severity bound = %#v", args[3])
	}
	if observed, ok := args[4].([]string); !ok || observed[0] != "critical" {
		t.Fatalf("observed_severity bound = %#v", args[4])
	}
	if n, ok := args[5].(int64); !ok || n != 1 {
		t.Fatalf("times_mitigated bound = %#v", args[5])
	}
	if n, ok := args[6].(int64); !ok || n != 1 {
		t.Fatalf("occurrence_count bound = %#v", args[6])
	}
	if b, ok := args[7].(bool); !ok || b {
		t.Fatalf("auto_mitigation_eligible bound = %#v", args[7])
	}

	isRecast, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "recast_severity", Op: "is_not_empty"},
	}}}}, &[]any{})
	if err != nil {
		t.Fatalf("is recast: %v", err)
	}
	if !strings.Contains(isRecast, "(l.recast_severity IS NOT NULL AND l.recast_severity <> '')") {
		t.Fatalf("is_not_empty recast SQL = %s", isRecast)
	}
	notRecast, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{
		{Field: "recast_severity", Op: "is_empty"},
	}}}}, &[]any{})
	if err != nil {
		t.Fatalf("is not recast: %v", err)
	}
	if !strings.Contains(notRecast, "(l.recast_severity IS NULL OR l.recast_severity = '')") {
		t.Fatalf("is_empty recast SQL = %s", notRecast)
	}

	rejected := []FindingCondition{
		{Field: "times_mitigated", Op: "any_of", Values: []string{"1"}},
		{Field: "times_mitigated", Op: "gte", Values: []string{"1.5"}},
		{Field: "times_mitigated", Op: "gte", Values: []string{"one"}},
		{Field: "times_mitigated", Op: "gte", Values: []string{"1", "2"}},
		{Field: "occurrence_count", Op: "contains", Values: []string{"1"}},
		{Field: "auto_mitigation_eligible", Op: "any_of", Values: []string{"false"}},
		{Field: "auto_mitigation_eligible", Op: "is", Values: []string{"yes"}},
		{Field: "auto_mitigation_eligible", Op: "is", Values: []string{"true", "false"}},
		{Field: "recast_severity", Op: "contains", Values: []string{"low"}},
		{Field: "observed_severity", Op: "gte", Values: []string{"1"}},
		{Field: "accept_expires_at", Op: "eq", Values: []string{"1"}},
		{Field: "severity", Op: "is_empty"},
	}
	for _, cond := range rejected {
		var bound []any
		_, err := buildFindingWhere(FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{cond}}}}, &bound)
		if err == nil {
			t.Fatalf("condition %+v compiled, want validation error", cond)
		}
	}
}
