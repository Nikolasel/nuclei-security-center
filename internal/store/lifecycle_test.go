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

func TestValidStatus(t *testing.T) {
	for _, s := range []string{"open", "triaged", "false_positive", "fixed"} {
		if !ValidStatus(s) {
			t.Errorf("ValidStatus(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "OPEN", "resolved", "new", "bogus"} {
		if ValidStatus(s) {
			t.Errorf("ValidStatus(%q) = true, want false", s)
		}
	}
}
