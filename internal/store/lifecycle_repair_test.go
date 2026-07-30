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
		coveredByScan       map[string]bool
		occByScan           map[string]int64
		wantFirst, wantLast *string
		wantOcc             *int64
		wantCovering        *string
		wantMitigated       int
	}{
		{
			name:      "no surviving occurrences at all",
			scanIDs:   []string{"s1", "s2"},
			occByScan: map[string]int64{},
			wantFirst: nil, wantLast: nil, wantOcc: nil, wantMitigated: 0,
			wantCovering: str("s2"),
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
			wantCovering: str("s3"),
		},
		{
			name:      "present in every surviving scan",
			scanIDs:   []string{"s1", "s2", "s3"},
			occByScan: map[string]int64{"s1": 1, "s2": 2, "s3": 3},
			wantFirst: str("s1"), wantLast: str("s3"), wantOcc: i64(3), wantMitigated: 0,
			wantCovering: str("s3"),
		},
		{
			// Present, then absent, and never comes back: mitigated, but never
			// resurfaced (times_mitigated only bumps on reappearance).
			name:      "present then absent, no return",
			scanIDs:   []string{"s1", "s2", "s3"},
			occByScan: map[string]int64{"s1": 1},
			wantFirst: str("s1"), wantLast: str("s1"), wantOcc: i64(1), wantMitigated: 0,
			wantCovering: str("s3"),
		},
		{
			name:      "one mitigation-then-reappear cycle",
			scanIDs:   []string{"s1", "s2", "s3"},
			occByScan: map[string]int64{"s1": 1, "s3": 3},
			wantFirst: str("s1"), wantLast: str("s3"), wantOcc: i64(3), wantMitigated: 1,
			wantCovering: str("s3"),
		},
		{
			name:      "two mitigation-then-reappear cycles",
			scanIDs:   []string{"s1", "s2", "s3", "s4", "s5"},
			occByScan: map[string]int64{"s1": 1, "s3": 3, "s5": 5},
			wantFirst: str("s1"), wantLast: str("s5"), wantOcc: i64(5), wantMitigated: 2,
			wantCovering: str("s5"),
		},
		{
			// Absent from the very first surviving scan, then observed later:
			// that first appearance is "new", not a resurface — there's no
			// earlier presence for it to have regressed from.
			name:      "absent from first scan, appears later",
			scanIDs:   []string{"s1", "s2"},
			occByScan: map[string]int64{"s2": 2},
			wantFirst: str("s2"), wantLast: str("s2"), wantOcc: i64(2), wantMitigated: 0,
			wantCovering: str("s2"),
		},
		{
			// A scan that did not include this template is not evidence of
			// mitigation, so the next observation remains continuously active.
			name:          "uncovered gap does not create mitigation cycle",
			scanIDs:       []string{"s1", "s2", "s3"},
			coveredByScan: map[string]bool{"s1": true, "s3": true},
			occByScan:     map[string]int64{"s1": 1, "s3": 3},
			wantFirst:     str("s1"), wantLast: str("s3"), wantOcc: i64(3), wantMitigated: 0,
			wantCovering: str("s3"),
		},
		{
			name:          "covered gap creates mitigation cycle",
			scanIDs:       []string{"s1", "s2", "s3"},
			coveredByScan: map[string]bool{"s1": true, "s2": true, "s3": true},
			occByScan:     map[string]int64{"s1": 1, "s3": 3},
			wantFirst:     str("s1"), wantLast: str("s3"), wantOcc: i64(3), wantMitigated: 1,
			wantCovering: str("s3"),
		},
		{
			// Occurrences from pre-catalog scans prove that the template ran,
			// while an unobserved legacy scan with no concrete ids proves
			// nothing and is ignored.
			name:          "legacy occurrences prove coverage",
			scanIDs:       []string{"s1", "s2", "s3"},
			coveredByScan: map[string]bool{"s1": true, "s3": true},
			occByScan:     map[string]int64{"s1": 1, "s3": 3},
			wantFirst:     str("s1"), wantLast: str("s3"), wantOcc: i64(3), wantMitigated: 0,
			wantCovering: str("s3"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			coveredByScan := c.coveredByScan
			if coveredByScan == nil {
				coveredByScan = make(map[string]bool, len(c.scanIDs))
				for _, scanID := range c.scanIDs {
					coveredByScan[scanID] = true
				}
			}
			covered := func(scanID string) bool { return coveredByScan[scanID] }
			gotFirst, gotLast, gotOcc, gotCovering, gotMitigated := computeLifecycleTimeline(
				c.scanIDs, covered, c.occByScan)
			if !strPtrEqual(gotFirst, c.wantFirst) {
				t.Errorf("firstSeenScan = %s, want %s", fmtStrPtr(gotFirst), fmtStrPtr(c.wantFirst))
			}
			if !strPtrEqual(gotLast, c.wantLast) {
				t.Errorf("lastSeenScan = %s, want %s", fmtStrPtr(gotLast), fmtStrPtr(c.wantLast))
			}
			if !i64PtrEqual(gotOcc, c.wantOcc) {
				t.Errorf("latestOccurrenceID = %s, want %s", fmtI64Ptr(gotOcc), fmtI64Ptr(c.wantOcc))
			}
			if !strPtrEqual(gotCovering, c.wantCovering) {
				t.Errorf("lastCoveringScan = %s, want %s", fmtStrPtr(gotCovering), fmtStrPtr(c.wantCovering))
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
