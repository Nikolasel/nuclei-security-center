package store

import "testing"

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
