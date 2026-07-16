package store

import (
	"fmt"
	"testing"
)

// TestComputeLifecycleTimeline pins the recompute rule used when a scan delete
// leaves a finding's history pointing at scans that no longer exist (#65's
// scan-delete feature interacting with the read-time detection-state model in
// lifecycle.go). scanIDs is oldest-first; occByScan marks which of those scans
// still carry an occurrence of the finding.
func TestComputeLifecycleTimeline(t *testing.T) {
	str := func(s string) *string { return &s }
	i64 := func(n int64) *int64 { return &n }

	cases := []struct {
		name                string
		scanIDs             []string
		occByScan           map[string]int64
		wantFirst, wantLast *string
		wantOcc             *int64
		wantMitigated       int
	}{
		{
			name:      "no surviving occurrences at all",
			scanIDs:   []string{"s1", "s2"},
			occByScan: map[string]int64{},
			wantFirst: nil, wantLast: nil, wantOcc: nil, wantMitigated: 0,
		},
		{
			// The exact bug this repair targets: everything but one scan got
			// deleted, and the finding was observed in the sole survivor. It
			// must read as first appearance ("new"), not a resurfaced regression
			// nothing left can substantiate.
			name:      "single surviving scan, present",
			scanIDs:   []string{"s3"},
			occByScan: map[string]int64{"s3": 100},
			wantFirst: str("s3"), wantLast: str("s3"), wantOcc: i64(100), wantMitigated: 0,
		},
		{
			name:      "present in every surviving scan",
			scanIDs:   []string{"s1", "s2", "s3"},
			occByScan: map[string]int64{"s1": 1, "s2": 2, "s3": 3},
			wantFirst: str("s1"), wantLast: str("s3"), wantOcc: i64(3), wantMitigated: 0,
		},
		{
			// Present, then absent, and never comes back: mitigated, but never
			// resurfaced (times_mitigated only bumps on reappearance).
			name:      "present then absent, no return",
			scanIDs:   []string{"s1", "s2", "s3"},
			occByScan: map[string]int64{"s1": 1},
			wantFirst: str("s1"), wantLast: str("s1"), wantOcc: i64(1), wantMitigated: 0,
		},
		{
			name:      "one mitigation-then-reappear cycle",
			scanIDs:   []string{"s1", "s2", "s3"},
			occByScan: map[string]int64{"s1": 1, "s3": 3},
			wantFirst: str("s1"), wantLast: str("s3"), wantOcc: i64(3), wantMitigated: 1,
		},
		{
			name:      "two mitigation-then-reappear cycles",
			scanIDs:   []string{"s1", "s2", "s3", "s4", "s5"},
			occByScan: map[string]int64{"s1": 1, "s3": 3, "s5": 5},
			wantFirst: str("s1"), wantLast: str("s5"), wantOcc: i64(5), wantMitigated: 2,
		},
		{
			// Absent from the very first surviving scan, then observed later:
			// that first appearance is "new", not a resurface — there's no
			// earlier presence for it to have regressed from.
			name:      "absent from first scan, appears later",
			scanIDs:   []string{"s1", "s2"},
			occByScan: map[string]int64{"s2": 2},
			wantFirst: str("s2"), wantLast: str("s2"), wantOcc: i64(2), wantMitigated: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotFirst, gotLast, gotOcc, gotMitigated := computeLifecycleTimeline(c.scanIDs, c.occByScan)
			if !strPtrEqual(gotFirst, c.wantFirst) {
				t.Errorf("firstSeenScan = %s, want %s", fmtStrPtr(gotFirst), fmtStrPtr(c.wantFirst))
			}
			if !strPtrEqual(gotLast, c.wantLast) {
				t.Errorf("lastSeenScan = %s, want %s", fmtStrPtr(gotLast), fmtStrPtr(c.wantLast))
			}
			if !i64PtrEqual(gotOcc, c.wantOcc) {
				t.Errorf("latestOccurrenceID = %s, want %s", fmtI64Ptr(gotOcc), fmtI64Ptr(c.wantOcc))
			}
			if gotMitigated != c.wantMitigated {
				t.Errorf("timesMitigated = %d, want %d", gotMitigated, c.wantMitigated)
			}
		})
	}
}

func strPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func fmtStrPtr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q", *p)
}

func i64PtrEqual(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func fmtI64Ptr(p *int64) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%d", *p)
}
