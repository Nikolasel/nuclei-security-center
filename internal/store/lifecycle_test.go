package store

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestBuildFindingWhere(t *testing.T) {
	// Empty query → no WHERE, no args.
	var args []any
	if w, err := buildFindingWhere(FindingQuery{}, &args); err != nil || w != "" || len(args) != 0 {
		t.Fatalf("empty query: where=%q args=%v err=%v", w, args, err)
	}

	// OR-of-AND: (severity any_of [critical,high] AND host contains scanme)
	// OR (cve is_empty). Groups are parenthesized + OR-joined; conditions AND-joined.
	args = nil
	q := FindingQuery{Groups: []FindingGroup{
		{Conditions: []FindingCondition{
			{Field: "severity", Op: "any_of", Values: []string{"Critical", "High"}},
			{Field: "host", Op: "contains", Values: []string{"scanme.sh"}},
		}},
		{Conditions: []FindingCondition{
			{Field: "cve", Op: "is_empty"},
		}},
	}}
	where, err := buildFindingWhere(q, &args)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, want := range []string{
		"lower(coalesce(l.recast_severity, l.severity)) = ANY($1)",
		"l.host ILIKE ANY($2)",
		") OR (",                         // two groups OR-joined
		" AND ",                          // conditions within group 1 AND-joined
		"array_length(l.cve, 1), 0) = 0", // cve is_empty, no bind
	} {
		if !strings.Contains(where, want) {
			t.Errorf("where missing %q:\n%s", want, where)
		}
	}
	if len(args) != 2 { // only severity + host bind; is_empty binds nothing
		t.Fatalf("want 2 bind args, got %d: %v", len(args), args)
	}
	if sev := args[0].([]string); sev[0] != "critical" || sev[1] != "high" {
		t.Errorf("severities not lowercased: %v", args[0])
	}
	if hosts := args[1].([]string); hosts[0] != "%scanme.sh%" {
		t.Errorf("host not wrapped for substring: %v", args[1])
	}

	// Unknown field / operator / missing value are validation errors.
	bad := []FindingQuery{
		{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "bogus", Op: "any_of", Values: []string{"x"}}}}}},
		{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "severity", Op: "contains", Values: []string{"x"}}}}}},
		{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "severity", Op: "any_of"}}}}},
	}
	for i, q := range bad {
		var a []any
		if _, err := buildFindingWhere(q, &a); err == nil {
			t.Errorf("bad query %d compiled without error", i)
		}
	}
}

// TestDedupKey pins the exact string form of the dedup key. The backfill in
// migration 0005 computes the same key in SQL —
//
//	coalesce(target_id::text,'-') || E'\x1f' || template_id || E'\x1f' || coalesce(matched_at,'')
//
// — so if this format ever changes, that migration must change in lockstep or
// re-observed findings would fork into new lifecycle rows.
func TestDedupKey(t *testing.T) {
	const us = "\x1f"
	cases := []struct {
		name                            string
		targetID, templateID, matchedAt string
		want                            string
	}{
		{"with target", "t1", "tpl", "https://h/p", "t1" + us + "tpl" + us + "https://h/p"},
		{"empty target collapses to dash", "", "tpl", "h:443", "-" + us + "tpl" + us + "h:443"},
		{"empty matched-at", "t1", "tpl", "", "t1" + us + "tpl" + us + ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DedupKey(c.targetID, c.templateID, c.matchedAt); got != c.want {
				t.Errorf("DedupKey(%q,%q,%q) = %q, want %q", c.targetID, c.templateID, c.matchedAt, got, c.want)
			}
		})
	}
}

// TestDedupKeyControlCharInjection asserts a matched_at carrying the 0x1f
// separator can't be steered to collide with a different (target,template,
// matched_at) tuple's key.
func TestDedupKeyControlCharInjection(t *testing.T) {
	// Raw concatenation would make these two tuples share a key:
	//   A: ("t", "a", "b\x1fc")   -> t \x1f a \x1f b \x1f c
	//   B: ("t", "a\x1fb", "c")   -> t \x1f a \x1f b \x1f c
	a := DedupKey("t", "a", "b\x1fc")
	b := DedupKey("t", "a\x1fb", "c")
	if a == b {
		t.Fatalf("distinct tuples collide after 0x1f injection: %q", a)
	}

	// The separator must not survive inside any component.
	if got := DedupKey("t", "a", "b\x1fc"); got != "t\x1fa\x1fbc" {
		t.Errorf("control char not stripped: %q", got)
	}

	// A realistic value (no control chars) is untouched — key parity with the
	// migration 0005 backfill is preserved.
	if got := DedupKey("uuid", "cve-2021-1", "https://h/p"); got != "uuid\x1fcve-2021-1\x1fhttps://h/p" {
		t.Errorf("realistic key changed: %q", got)
	}
}

func TestFindingJSONBProjectionEscapesNULWithoutChangingRaw(t *testing.T) {
	raw := []byte(`{"template-id":"nul-test","matcher":"a\u0000b","literal":"a\\u0000b","large":12345678901234567890}`)
	original := append([]byte(nil), raw...)

	projected, err := findingJSONBProjection(raw)
	if err != nil {
		t.Fatalf("findingJSONBProjection: %v", err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatalf("raw input changed:\n got: %s\nwant: %s", raw, original)
	}

	dec := json.NewDecoder(bytes.NewReader(projected))
	dec.UseNumber()
	var got map[string]any
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode projection: %v", err)
	}
	if got["matcher"] != `a\0b` {
		t.Errorf("matcher = %q, want printable NUL marker", got["matcher"])
	}
	if got["literal"] != `a\u0000b` {
		t.Errorf("literal = %q, want existing literal escape unchanged", got["literal"])
	}
	if got["large"] != json.Number("12345678901234567890") {
		t.Errorf("large number changed: %#v", got["large"])
	}
}

func TestFindingRawLineNormalizesInvalidUTF8(t *testing.T) {
	raw := append([]byte(`{"template-id":"invalid-utf8","matcher":"a`), 0xff)
	raw = append(raw, []byte(`b"}`)...)

	got := findingRawLine(raw)
	if !utf8.ValidString(got) {
		t.Fatalf("findingRawLine returned invalid UTF-8: %q", got)
	}
	if want := `{"template-id":"invalid-utf8","matcher":"a�b"}`; got != want {
		t.Errorf("findingRawLine = %q, want %q", got, want)
	}

	projected, err := findingJSONBProjection(raw)
	if err != nil {
		t.Fatalf("findingJSONBProjection: %v", err)
	}
	if !utf8.Valid(projected) {
		t.Fatalf("JSONB projection contains invalid UTF-8: %q", projected)
	}
}

func TestFindingTextProjectionEscapesIndexedNUL(t *testing.T) {
	f := types.NucleiFinding{
		TemplateID: "id\x00suffix",
		Type:       "http\x00type",
		Host:       "host\x00name",
		MatchedAt:  "https://host/\x00",
		Info: types.NucleiInfo{
			Name:     "name\x00suffix",
			Severity: "high\x00suffix",
			Tags:     []string{"tag\x00suffix"},
			Classification: &types.NucleiClassification{
				CVEID: []string{"CVE\x00-1"},
				CWEID: []string{"CWE\x00-1"},
			},
		},
	}

	got := findingTextProjection(f)
	checks := map[string]string{
		"template id": got.TemplateID,
		"type":        got.Type,
		"host":        got.Host,
		"matched at":  got.MatchedAt,
		"name":        got.Info.Name,
		"severity":    got.Info.Severity,
		"tag":         got.Info.Tags[0],
		"CVE":         got.Info.Classification.CVEID[0],
		"CWE":         got.Info.Classification.CWEID[0],
	}
	for name, value := range checks {
		if strings.ContainsRune(value, '\x00') {
			t.Errorf("%s still contains NUL: %q", name, value)
		}
		if !strings.Contains(value, `\0`) {
			t.Errorf("%s = %q, want printable NUL marker", name, value)
		}
	}

	// The projection copies nested classification data rather than mutating the
	// parsed source value that may still be used for diagnostics.
	if f.Info.Classification.CVEID[0] != "CVE\x00-1" {
		t.Errorf("source classification mutated: %q", f.Info.Classification.CVEID[0])
	}
}

func TestValidDisposition(t *testing.T) {
	for _, d := range []string{"none", "false_positive", "accepted"} {
		if !ValidDisposition(d) {
			t.Errorf("ValidDisposition(%q) = false, want true", d)
		}
	}
	// "fixed"/"open" are gone — closure is evidence-driven (Mitigated), not manual.
	for _, d := range []string{"", "open", "fixed", "resolved", "ACCEPTED", "bogus"} {
		if ValidDisposition(d) {
			t.Errorf("ValidDisposition(%q) = true, want false", d)
		}
	}
}

func TestValidSeverity(t *testing.T) {
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if !ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "CRITICAL", "none", "informational"} {
		if ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = true, want false", s)
		}
	}
}
