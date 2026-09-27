package store

import (
	"fmt"
	"strings"
	"time"
)

// FindingQuery is a structured findings filter (#97): OR-of-AND groups. Groups
// are ORed; conditions within a group are ANDed — so it compiles to
// `(c AND c) OR (c) OR (c AND c)`. An empty query (no groups / no conditions)
// matches everything. The whole tree arrives as one JSON param and is compiled
// to a fully parameterized WHERE clause — user values never touch the SQL text.
type FindingQuery struct {
	Groups []FindingGroup `json:"groups"`
	// Sort and Order come from the URL (not the filter JSON) so the list and
	// export stay in lockstep. Empty Sort keeps the historical default order.
	Sort  string `json:"-"`
	Order string `json:"-"`
}

// FindingGroup is a set of AND-ed conditions (one OR-clause of the query).
type FindingGroup struct {
	Conditions []FindingCondition `json:"conditions"`
}

// FindingCondition is a single `field op values` predicate. Values is any-of
// within the condition (e.g. severity any_of [critical,high]); is_empty /
// is_not_empty take no values.
type FindingCondition struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values,omitempty"`
}

// These limits cap every value dimension that can amplify the generated
// PostgreSQL work (CWE-770). They are generous for the condition-builder UI but
// keep one viewer request from binding an unbounded text array or ILIKE pattern
// list.
const (
	maxConditions         = 60
	maxValuesPerCondition = 100
	maxFilterValueBytes   = 256
)

// fieldKind classifies how a field is stored, which decides its operator set and
// SQL shape.
type fieldKind int

const (
	kindEnum      fieldKind = iota // scalar compared exactly (severity/state/disposition/type)
	kindText                       // scalar substring (host, matched_at)
	kindTextTwo                    // substring over two columns (name OR template)
	kindTextArray                  // text[] membership/substring (cve, tag)
	kindTarget                     // occurrence provenance target membership
	kindTime                       // timestamptz range (first_seen_at / last_seen_at)
)

// fieldSpec maps a filter field name to the SQL it filters on. expr is the column
// expression (for scalar kinds); exprB is the second column for kindTextTwo;
// lowered lowercases both the column and the bound values (severity is stored
// mixed-case but compared case-insensitively).
type fieldSpec struct {
	kind    fieldKind
	expr    string
	exprB   string
	lowered bool
}

// findingFields is the allowlist: only these fields are filterable, and each maps
// to a fixed SQL expression — an unknown field is rejected, so the field name can
// never be attacker-controlled SQL.
var findingFields = map[string]fieldSpec{
	"name":             {kind: kindTextTwo, expr: "l.name", exprB: "l.template_id"},
	"severity":         {kind: kindEnum, expr: effSevExpr, lowered: true},
	"state":            {kind: kindEnum, expr: "(" + lcEffectiveExpr + ")"},
	"disposition":      {kind: kindEnum, expr: "l.disposition"},
	"target":           {kind: kindTarget},
	"host":             {kind: kindText, expr: "l.host"},
	"matcher":          {kind: kindText, expr: "l.matcher_name"},
	"extracted_result": {kind: kindTextArray, expr: "l.extracted_results"},
	"matched_at":       {kind: kindText, expr: "l.matched_at"},
	"type":             {kind: kindEnum, expr: "l.type", lowered: true},
	"cve":              {kind: kindTextArray, expr: "l.cve"},
	"tag":              {kind: kindTextArray, expr: "l.tags"},
	"first_seen_at":    {kind: kindTime, expr: "l.first_seen_at"},
	"last_seen_at":     {kind: kindTime, expr: "l.last_seen_at"},
}

// opsForKind lists the operators each field kind accepts (also drives the UI).
var opsForKind = map[fieldKind]map[string]bool{
	kindEnum:      {"any_of": true, "none_of": true},
	kindText:      {"contains": true, "not_contains": true, "starts_with": true, "is_empty": true, "is_not_empty": true},
	kindTextTwo:   {"contains": true, "not_contains": true, "starts_with": true, "is_empty": true, "is_not_empty": true},
	kindTextArray: {"any_of": true, "none_of": true, "contains": true, "not_contains": true, "is_empty": true, "is_not_empty": true},
	kindTarget:    {"any_of": true, "none_of": true},
	kindTime:      {"before": true, "after": true, "between": true},
}

// findingSortColumns is the ORDER BY allowlist. Keys are the public `sort`
// values; expressions are fixed SQL (never user text). The findings table
// header uses the first catalog sort field for each column; this map is the
// SQL-safety gate and may include API-only keys (times_mitigated) that have
// no column.
var findingSortColumns = map[string]string{
	"first_seen_at":   "l.first_seen_at",
	"last_seen_at":    "l.last_seen_at",
	"severity":        effSevOrder,
	"matched_at":      "l.matched_at",
	"name":            "l.name",
	"times_mitigated": "l.times_mitigated",
	"state":           "(" + lcEffectiveExpr + ")",
	"detection_state": "(" + lcDetectionExpr + ")",
	"host":            "l.host",
	"matcher_name":    "l.matcher_name",
}

func CanonicalFindingSortField(field string) string {
	switch field {
	case "effective_severity":
		return "severity"
	case "first_seen":
		return "first_seen_at"
	case "last_seen":
		return "last_seen_at"
	case "effective_state":
		return "state"
	case "matcher":
		return "matcher_name"
	default:
		return field
	}
}

func defaultFindingSortOrder(field string) string {
	switch field {
	case "severity", "last_seen_at", "first_seen_at", "times_mitigated":
		return "desc"
	default:
		return "asc"
	}
}

// ValidateFindingSort reports whether sort/order are allowlisted. Empty sort
// (and empty order) is the historical default.
func ValidateFindingSort(sort, order string) error {
	if sort == "" {
		if order != "" {
			return fmt.Errorf("order requires a sort field")
		}
		return nil
	}
	if _, ok := findingSortColumns[sort]; !ok {
		return fmt.Errorf("unknown sort field %q", sort)
	}
	switch order {
	case "", "asc", "desc":
		return nil
	default:
		return fmt.Errorf("order must be 'asc' or 'desc'")
	}
}

// ValidateFindingQuery reports whether a query compiles (all fields/operators
// known, values present where required) without running it — so the HTTP layer
// can reject a bad filter as a 400 before touching the database.
func ValidateFindingQuery(q FindingQuery) error {
	if err := ValidateFindingSort(q.Sort, q.Order); err != nil {
		return err
	}
	var args []any
	_, err := buildFindingWhere(q, &args)
	return err
}

// buildFindingWhere compiles the query into a parameterized WHERE clause,
// appending bind values onto *args. Returns "" for an empty query. An unknown
// field/operator or a malformed condition is a validation error (→ 400).
func buildFindingWhere(q FindingQuery, args *[]any) (string, error) {
	push := func(val any) int {
		*args = append(*args, val)
		return len(*args)
	}

	n := 0
	var orClauses []string
	for _, g := range q.Groups {
		var andConds []string
		for _, c := range g.Conditions {
			n++
			if n > maxConditions {
				return "", fmt.Errorf("too many filter conditions (max %d)", maxConditions)
			}
			sql, err := compileCondition(c, push)
			if err != nil {
				return "", err
			}
			andConds = append(andConds, sql)
		}
		if len(andConds) > 0 {
			orClauses = append(orClauses, "("+strings.Join(andConds, " AND ")+")")
		}
	}
	if len(orClauses) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(orClauses, " OR "), nil
}

// compileCondition renders one predicate. Every operand is bound via push(), so
// only the field/op (both allowlisted) reach the SQL text.
func compileCondition(c FindingCondition, push func(any) int) (string, error) {
	spec, ok := findingFields[c.Field]
	if !ok {
		return "", fmt.Errorf("unknown filter field %q", c.Field)
	}
	if !opsForKind[spec.kind][c.Op] {
		return "", fmt.Errorf("operator %q not valid for field %q", c.Op, c.Field)
	}
	if err := validateFilterValues(c.Values); err != nil {
		return "", err
	}

	// is_empty / is_not_empty: no values.
	switch c.Op {
	case "is_empty":
		return emptyExpr(spec, true), nil
	case "is_not_empty":
		return emptyExpr(spec, false), nil
	}

	vals := trimNonEmpty(c.Values)
	if len(vals) == 0 {
		return "", fmt.Errorf("field %q operator %q needs at least one value", c.Field, c.Op)
	}
	if spec.lowered {
		for i, v := range vals {
			vals[i] = strings.ToLower(v)
		}
	}

	switch spec.kind {
	case kindEnum:
		col := spec.expr
		if spec.lowered {
			col = "lower(" + col + ")"
		}
		switch c.Op {
		case "any_of":
			return fmt.Sprintf("%s = ANY($%d)", col, push(vals)), nil
		case "none_of":
			return fmt.Sprintf("(%s IS NULL OR NOT (%s = ANY($%d)))", col, col, push(vals)), nil
		}

	case kindText, kindTextTwo:
		switch c.Op {
		case "contains":
			return anyLike(spec, likeWrap(vals, "%%%s%%"), push), nil
		case "not_contains":
			return "NOT (" + anyLike(spec, likeWrap(vals, "%%%s%%"), push) + ")", nil
		case "starts_with":
			return anyLike(spec, likeWrap(vals, "%s%%"), push), nil
		}

	case kindTextArray:
		switch c.Op {
		case "any_of": // exact membership overlap (tags)
			return fmt.Sprintf("%s && $%d::text[]", spec.expr, push(vals)), nil
		case "none_of":
			return fmt.Sprintf("NOT (%s && $%d::text[])", spec.expr, push(vals)), nil
		case "contains": // substring over any array element (cve)
			return fmt.Sprintf("EXISTS (SELECT 1 FROM unnest(%s) e WHERE e ILIKE ANY($%d))", spec.expr, push(likeWrap(vals, "%%%s%%"))), nil
		case "not_contains":
			return fmt.Sprintf("NOT EXISTS (SELECT 1 FROM unnest(%s) e WHERE e ILIKE ANY($%d))", spec.expr, push(likeWrap(vals, "%%%s%%"))), nil
		}

	case kindTarget:
		ph := push(vals)
		matches := fmt.Sprintf(
			`EXISTS (SELECT 1 FROM findings occurrence
			          WHERE occurrence.finding_id = l.id
			            AND occurrence.target_id::text = ANY($%d))`,
			ph)
		if c.Op == "none_of" {
			return "NOT (" + matches + ")", nil
		}
		return matches, nil

	case kindTime:
		return compileTimeCondition(spec.expr, c.Op, vals, push)
	}
	return "", fmt.Errorf("operator %q not valid for field %q", c.Op, c.Field)
}

func compileTimeCondition(col, op string, vals []string, push func(any) int) (string, error) {
	switch op {
	case "after", "before":
		if len(vals) != 1 {
			return "", fmt.Errorf("operator %q needs exactly one value", op)
		}
	case "between":
		if len(vals) != 2 {
			return "", fmt.Errorf("operator %q needs exactly two values", op)
		}
	}
	switch op {
	case "after":
		lo, err := afterInstant(vals[0])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s >= $%d", col, push(lo)), nil
	case "before":
		hi, exclusive, err := beforeCutoff(vals[0])
		if err != nil {
			return "", err
		}
		cmp := "<="
		if exclusive {
			cmp = "<"
		}
		return fmt.Sprintf("%s %s $%d", col, cmp, push(hi)), nil
	case "between":
		lo, err := afterInstant(vals[0])
		if err != nil {
			return "", err
		}
		hi, exclusive, err := beforeCutoff(vals[1])
		if err != nil {
			return "", err
		}
		last := hi
		if exclusive {
			last = hi.Add(-time.Nanosecond)
		}
		if lo.After(last) {
			return "", fmt.Errorf("between range is inverted")
		}
		cmp := "<="
		if exclusive {
			cmp = "<"
		}
		return fmt.Sprintf("%s >= $%d AND %s %s $%d", col, push(lo), col, cmp, push(hi)), nil
	}
	return "", fmt.Errorf("operator %q not valid for time field", op)
}

func parseFilterTime(s string) (time.Time, bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false, fmt.Errorf("invalid time %q (want RFC3339 or YYYY-MM-DD)", s)
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), false, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), true, nil
	}
	return time.Time{}, false, fmt.Errorf("invalid time %q (want RFC3339 or YYYY-MM-DD)", s)
}

func afterInstant(s string) (time.Time, error) {
	t, _, err := parseFilterTime(s)
	return t, err
}

// beforeCutoff returns the upper bound for an inclusive before/between end.
// Date-only values include the whole UTC day via an exclusive next-midnight cutoff.
func beforeCutoff(s string) (time.Time, bool, error) {
	t, dateOnly, err := parseFilterTime(s)
	if err != nil {
		return time.Time{}, false, err
	}
	if dateOnly {
		return t.AddDate(0, 0, 1), true, nil
	}
	return t, false, nil
}

func validateFilterValues(values []string) error {
	if len(values) > maxValuesPerCondition {
		return fmt.Errorf("too many filter values (max %d)", maxValuesPerCondition)
	}
	for _, value := range values {
		if len(value) > maxFilterValueBytes {
			return fmt.Errorf("filter value exceeds %d-byte limit", maxFilterValueBytes)
		}
	}
	return nil
}

// anyLike builds `col ILIKE ANY($n)` (and the two-column OR for kindTextTwo).
func anyLike(spec fieldSpec, patterns []string, push func(any) int) string {
	ph := push(patterns)
	if spec.kind == kindTextTwo {
		return fmt.Sprintf("(%s ILIKE ANY($%d) OR %s ILIKE ANY($%d))", spec.expr, ph, spec.exprB, ph)
	}
	return fmt.Sprintf("%s ILIKE ANY($%d)", spec.expr, ph)
}

// emptyExpr renders is_empty / is_not_empty for a field.
func emptyExpr(spec fieldSpec, empty bool) string {
	if spec.kind == kindTextArray {
		if empty {
			return fmt.Sprintf("coalesce(array_length(%s, 1), 0) = 0", spec.expr)
		}
		return fmt.Sprintf("coalesce(array_length(%s, 1), 0) > 0", spec.expr)
	}
	if spec.kind == kindTextTwo {
		// Emptiness is the display name only. template_id is NOT NULL on every
		// finding, so requiring both columns blank would make is_empty match
		// nothing and is_not_empty match everything. contains / not_contains
		// still search name OR template_id (see anyLike).
		if empty {
			return fmt.Sprintf("(%s IS NULL OR %s = '')", spec.expr, spec.expr)
		}
		return fmt.Sprintf("(%s IS NOT NULL AND %s <> '')", spec.expr, spec.expr)
	}
	if empty {
		return fmt.Sprintf("(%s IS NULL OR %s = '')", spec.expr, spec.expr)
	}
	return fmt.Sprintf("(%s IS NOT NULL AND %s <> '')", spec.expr, spec.expr)
}

// escapeLike escapes LIKE/ILIKE metacharacters so user input is matched
// literally. Backslash is escaped first to avoid double-escaping the
// introducers for \% and \_.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// likeWrap formats each value into a LIKE pattern (e.g. "%%%s%%" → %v%)
// after escaping LIKE metacharacters so the value is matched literally.
// The surrounding % wildcards remain unescaped; the ILIKE call sites rely
// on PostgreSQL's default backslash escape (explicit ESCAPE is added where
// the syntax permits; ILIKE ANY cannot carry an ESCAPE clause).
func likeWrap(vals []string, format string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		escaped := escapeLike(v)
		out[i] = fmt.Sprintf(format, escaped)
	}
	return out
}

// trimNonEmpty trims whitespace and drops empty entries.
func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
