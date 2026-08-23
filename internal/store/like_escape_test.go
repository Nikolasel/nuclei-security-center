package store

import (
	"strings"
	"testing"
)

func TestEscapeLike(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "plain", in: "abc", want: "abc"},
		{name: "percent", in: "a%b", want: "a\\%b"},
		{name: "underscore", in: "a_b", want: "a\\_b"},
		{name: "backslash", in: "a\\b", want: "a\\\\b"},
		{name: "percent with backslash", in: "a\\%b", want: "a\\\\\\%b"},
		{name: "underscore with backslash", in: "a\\_b", want: "a\\\\\\_b"},
		{name: "trailing backslash", in: "abc\\", want: "abc\\\\"},
		{name: "single percent", in: "%", want: "\\%"},
		{name: "single underscore", in: "_", want: "\\_"},
		{name: "single backslash", in: "\\", want: "\\\\"},
		{name: "all three", in: "%_\\", want: "\\%\\_\\\\"},
		{name: "multiple percents", in: "%%", want: "\\%\\%"},
		{name: "multiple underscores", in: "__", want: "\\_\\_"},
		{name: "complex", in: "host%_\\end", want: "host\\%\\_\\\\end"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := escapeLike(tc.in); got != tc.want {
				t.Fatalf("escapeLike(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// Order matters: backslash must be escaped first, otherwise \% would be double-escaped incorrectly.
	t.Run("order backslash first", func(t *testing.T) {
		// If % were escaped first, then backslash-escape would double the introduced backslash.
		// The correct result for "%" is "\%", not "\\%".
		if got := escapeLike("%"); got != "\\%" {
			t.Fatalf("order check failed: escapeLike(\"%%\") = %q", got)
		}
		if got := escapeLike("\\%"); got != "\\\\\\%" {
			t.Fatalf("order check failed: escapeLike(\"\\\\%%\") = %q", got)
		}
	})
}

func TestLikeWrap(t *testing.T) {
	cases := []struct {
		name   string
		vals   []string
		format string
		want   []string
	}{
		{name: "contains percent", vals: []string{"a%b"}, format: "%%%s%%", want: []string{"%a\\%b%"}},
		{name: "contains underscore", vals: []string{"a_b"}, format: "%%%s%%", want: []string{"%a\\_b%"}},
		{name: "contains backslash", vals: []string{"a\\b"}, format: "%%%s%%", want: []string{"%a\\\\b%"}},
		{name: "contains trailing backslash", vals: []string{"abc\\"}, format: "%%%s%%", want: []string{"%abc\\\\%"}},
		{name: "starts_with percent", vals: []string{"a%b"}, format: "%s%%", want: []string{"a\\%b%"}},
		{name: "starts_with underscore", vals: []string{"a_b"}, format: "%s%%", want: []string{"a\\_b%"}},
		{name: "starts_with backslash", vals: []string{"a\\b"}, format: "%s%%", want: []string{"a\\\\b%"}},
		{name: "multiple values", vals: []string{"a%b", "c_d", "e\\f"}, format: "%%%s%%", want: []string{"%a\\%b%", "%c\\_d%", "%e\\\\f%"}},
		{name: "complex mixed", vals: []string{"%_\\"}, format: "%%%s%%", want: []string{"%\\%\\_\\\\%"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := likeWrap(tc.vals, tc.format)
			if len(got) != len(tc.want) {
				t.Fatalf("likeWrap(%v, %q) = %v, want %v", tc.vals, tc.format, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("likeWrap(%v, %q)[%d] = %q, want %q", tc.vals, tc.format, i, got[i], tc.want[i])
				}
			}
		})
	}
	t.Run("preserves surrounding wildcards literally", func(t *testing.T) {
		got := likeWrap([]string{"x"}, "%%%s%%")
		if got[0] != "%x%" {
			t.Fatalf("contains format not preserving outer %%: %q", got[0])
		}
		if !strings.HasPrefix(got[0], "%") || !strings.HasSuffix(got[0], "%") {
			t.Fatalf("contains should wrap with %%: %q", got[0])
		}
		got = likeWrap([]string{"x"}, "%s%%")
		if got[0] != "x%" {
			t.Fatalf("starts_with format = %q, want %q", got[0], "x%")
		}
		if strings.HasPrefix(got[0], "%") {
			t.Fatalf("starts_with should not prefix with %%: %q", got[0])
		}
	})
}

func TestBuildFindingWhereEscapesLikeMetacharacters(t *testing.T) {
	// Each metacharacter must be escaped in the bound pattern, and the SQL must
	// stay parameterized (placeholders, not inline values). ILIKE ANY cannot
	// carry an explicit ESCAPE clause, so the test verifies default backslash
	// escaping via the bound value.
	cases := []struct {
		name    string
		query   FindingQuery
		wantPat string // expected single pattern in args[0].([]string)[0]
		field   string
		op      string
	}{
		{name: "host contains percent", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "contains", Values: []string{"a%b"}}}}}}, wantPat: "%a\\%b%", field: "host", op: "contains"},
		{name: "host contains underscore", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "contains", Values: []string{"a_b"}}}}}}, wantPat: "%a\\_b%", field: "host", op: "contains"},
		{name: "host contains backslash", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "contains", Values: []string{"a\\b"}}}}}}, wantPat: "%a\\\\b%", field: "host", op: "contains"},
		{name: "host contains trailing backslash", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "contains", Values: []string{"abc\\"}}}}}}, wantPat: "%abc\\\\%", field: "host", op: "contains"},
		{name: "host starts_with percent", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "starts_with", Values: []string{"a%b"}}}}}}, wantPat: "a\\%b%", field: "host", op: "starts_with"},
		{name: "name contains percent", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "name", Op: "contains", Values: []string{"a%b"}}}}}}, wantPat: "%a\\%b%", field: "name", op: "contains"},
		{name: "cve contains underscore", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "cve", Op: "contains", Values: []string{"CVE_2021"}}}}}}, wantPat: "%CVE\\_2021%", field: "cve", op: "contains"},
		{name: "cve not_contains percent", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "cve", Op: "not_contains", Values: []string{"CVE%"}}}}}}, wantPat: "%CVE\\%%", field: "cve", op: "not_contains"},
		{name: "host not_contains trailing backslash", query: FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "not_contains", Values: []string{"x\\"}}}}}}, wantPat: "%x\\\\%", field: "host", op: "not_contains"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var args []any
			where, err := buildFindingWhere(tc.query, &args)
			if err != nil {
				t.Fatalf("buildFindingWhere error: %v", err)
			}
			if len(args) == 0 {
				t.Fatalf("no args produced for %s", tc.name)
			}
			// The LIKE patterns are bound as text[] at $1 (or similar).
			patterns, ok := args[0].([]string)
			if !ok {
				t.Fatalf("args[0] is %T, want []string", args[0])
			}
			if len(patterns) != 1 || patterns[0] != tc.wantPat {
				t.Fatalf("pattern = %v, want [%q]", patterns, tc.wantPat)
			}
			// SQL must be parameterized: placeholder and not inline raw value.
			if !strings.Contains(where, "$1") {
				t.Fatalf("where missing placeholder: %q", where)
			}
			if strings.Contains(where, tc.query.Groups[0].Conditions[0].Values[0]) && !strings.Contains(tc.query.Groups[0].Conditions[0].Values[0], "%") {
				// For values without metachars this could happen, but for our cases the raw unescaped should not appear.
			}
			// Verify the raw unescaped LIKE pattern does not leak into SQL text.
			// The SQL text should only contain placeholders and fixed expressions.
			if strings.Contains(where, "'%") {
				t.Fatalf("where leaks inline pattern: %q", where)
			}
			// For host/name/cve LIKE predicates, the where should contain ILIKE ANY.
			if !strings.Contains(where, "ILIKE ANY") {
				t.Fatalf("where missing ILIKE ANY: %q", where)
			}
			// ILIKE ANY cannot carry ESCAPE per Postgres docs — relies on default backslash.
			if strings.Contains(where, "ESCAPE") {
				t.Fatalf("findingquery ILIKE ANY should not have explicit ESCAPE: %q", where)
			}
		})
	}
}

func TestTemplateFilterWhereEscapesLike(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		wantPat string
	}{
		{name: "percent", query: "a%b", wantPat: "%a\\%b%"},
		{name: "underscore", query: "a_b", wantPat: "%a\\_b%"},
		{name: "backslash", query: "a\\b", wantPat: "%a\\\\b%"},
		{name: "trailing backslash", query: "abc\\", wantPat: "%abc\\\\%"},
		{name: "all three", query: "%_\\", wantPat: "%\\%\\_\\\\%"},
		{name: "plain", query: "apache", wantPat: "%apache%"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			where, args := templateFilterWhere(TemplateFilter{Query: tc.query})
			if where == "" {
				t.Fatalf("empty where for query %q", tc.query)
			}
			if len(args) != 1 {
				t.Fatalf("args = %v, want 1", args)
			}
			if got, ok := args[0].(string); !ok || got != tc.wantPat {
				t.Fatalf("pattern = %v (%T), want %q", args[0], args[0], tc.wantPat)
			}
			// SQL must be parameterized and carry explicit ESCAPE.
			if !strings.Contains(where, "ILIKE") || !strings.Contains(where, "ESCAPE") {
				t.Fatalf("where missing ILIKE/ESCAPE: %q", where)
			}
			if !strings.Contains(where, "$1") {
				t.Fatalf("where missing placeholder: %q", where)
			}
			if strings.Contains(where, "'%") {
				t.Fatalf("where leaks inline pattern: %q", where)
			}
			// Ensure every ILIKE branch has ESCAPE.
			if count := strings.Count(where, "ESCAPE '\\'"); count != 3 {
				t.Fatalf("expected 3 ESCAPE clauses (id/name/description), got %d: %q", count, where)
			}
		})
	}
	t.Run("empty query produces no ILIKE", func(t *testing.T) {
		where, args := templateFilterWhere(TemplateFilter{Query: "   "})
		if strings.Contains(where, "ILIKE") {
			t.Fatalf("empty query should not add ILIKE: %q", where)
		}
		if len(args) != 0 {
			t.Fatalf("args for empty query = %v, want 0", args)
		}
	})
}

func TestOccurrenceFilterWhereEscapesLike(t *testing.T) {
	cases := []struct {
		name    string
		filter  FindingFilter
		wantPat string
		wantSQL string // substring that must appear in where
		argsIdx int    // index in args where pattern lives
	}{
		{name: "query percent", filter: FindingFilter{Query: "a%b"}, wantPat: "%a\\%b%", wantSQL: "name ILIKE", argsIdx: 0},
		{name: "query underscore", filter: FindingFilter{Query: "a_b"}, wantPat: "%a\\_b%", wantSQL: "name ILIKE", argsIdx: 0},
		{name: "query trailing backslash", filter: FindingFilter{Query: "abc\\"}, wantPat: "%abc\\\\%", wantSQL: "name ILIKE", argsIdx: 0},
		{name: "host percent", filter: FindingFilter{Host: "a%b"}, wantPat: "%a\\%b%", wantSQL: "host ILIKE", argsIdx: 0},
		{name: "host underscore", filter: FindingFilter{Host: "a_b"}, wantPat: "%a\\_b%", wantSQL: "host ILIKE", argsIdx: 0},
		{name: "host backslash", filter: FindingFilter{Host: "a\\b"}, wantPat: "%a\\\\b%", wantSQL: "host ILIKE", argsIdx: 0},
		{name: "cve percent", filter: FindingFilter{CVE: "CVE%"}, wantPat: "%CVE\\%%", wantSQL: "cve", argsIdx: 0},
		{name: "cve underscore", filter: FindingFilter{CVE: "CVE_2021"}, wantPat: "%CVE\\_2021%", wantSQL: "cve", argsIdx: 0},
		{name: "cve trailing backslash", filter: FindingFilter{CVE: "x\\"}, wantPat: "%x\\\\%", wantSQL: "cve", argsIdx: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			where, args := occurrenceFilterWhere(tc.filter)
			if where == "" {
				t.Fatalf("empty where for %+v", tc.filter)
			}
			if tc.argsIdx >= len(args) {
				t.Fatalf("args index %d out of range %v", tc.argsIdx, args)
			}
			got, ok := args[tc.argsIdx].(string)
			if !ok || got != tc.wantPat {
				t.Fatalf("pattern args[%d] = %v (%T), want %q; all args=%v", tc.argsIdx, args[tc.argsIdx], args[tc.argsIdx], tc.wantPat, args)
			}
			if !strings.Contains(where, tc.wantSQL) {
				t.Fatalf("where missing %q: %q", tc.wantSQL, where)
			}
			if !strings.Contains(where, "ESCAPE") {
				t.Fatalf("where missing ESCAPE: %q", where)
			}
			if !strings.Contains(where, "$") {
				t.Fatalf("where not parameterized: %q", where)
			}
			if strings.Contains(where, "'%") {
				t.Fatalf("where leaks inline pattern: %q", where)
			}
		})
	}
	t.Run("multiple fields combine with AND and increment placeholders", func(t *testing.T) {
		where, args := occurrenceFilterWhere(FindingFilter{Query: "a%b", Host: "c_d", CVE: "e\\f"})
		if len(args) != 3 {
			t.Fatalf("args = %v, want 3", args)
		}
		if args[0].(string) != "%a\\%b%" || args[1].(string) != "%c\\_d%" || args[2].(string) != "%e\\\\f%" {
			t.Fatalf("args patterns mismatch: %v", args)
		}
		if !strings.Contains(where, "AND") {
			t.Fatalf("combined where missing AND: %q", where)
		}
		// Each condition uses its own placeholder $1,$1,$2,$3 etc but placeholder numbers increment.
		// Query uses $1 twice, host $2, cve $3 => we should have $1, $2, $3 present.
		for _, ph := range []string{"$1", "$2", "$3"} {
			if !strings.Contains(where, ph) {
				t.Fatalf("where missing %s: %q", ph, where)
			}
		}
	})
}

func TestBuildFindingWhereLikeWrapFormats(t *testing.T) {
	// contains vs starts_with should differ only by trailing vs surrounding wildcards,
	// but both must escape the inner value.
	var args []any
	qContains := FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "contains", Values: []string{"a%b"}}}}}}
	qStarts := FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "starts_with", Values: []string{"a%b"}}}}}}
	_, _ = buildFindingWhere(qContains, &args)
	pContains := args[0].([]string)[0]
	args = nil
	_, _ = buildFindingWhere(qStarts, &args)
	pStarts := args[0].([]string)[0]
	if pContains != "%a\\%b%" {
		t.Fatalf("contains pattern = %q, want %%a\\%%b%%", pContains)
	}
	if pStarts != "a\\%b%" {
		t.Fatalf("starts_with pattern = %q, want a\\%%b%%", pStarts)
	}
}
