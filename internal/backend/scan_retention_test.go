package backend

import (
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/scanner"
)

// TestScanRetentionExceedsBackendOverhead asserts the cross-package invariant
// that the scanner's reclamation retention comfortably exceeds the backend's
// overhead between node terminal and eager reclaim (nodeOverhead+ingestTail).
// If nodeOverhead or ingestTail grows, this fails and forces a conscious
// bump of scanner.ScanRetention.
func TestScanRetentionExceedsBackendOverhead(t *testing.T) {
	overhead := nodeOverhead + ingestTail // 8m + 5m = 13m today
	if scanner.ScanRetention <= overhead {
		t.Fatalf("scanner.ScanRetention %s must exceed backend overhead %s (nodeOverhead %s + ingestTail %s)", scanner.ScanRetention, overhead, nodeOverhead, ingestTail)
	}
	// Keep retention generous (at least 2x overhead) so a transient stall
	// (Aurora pause) does not race the reaper.
	if scanner.ScanRetention < 2*overhead {
		t.Fatalf("scanner.ScanRetention %s should be at least 2x backend overhead %s for safety margin", scanner.ScanRetention, overhead)
	}
	// Also ensure it is exactly the documented 1h to catch accidental changes.
	if scanner.ScanRetention != time.Hour {
		t.Fatalf("scanner.ScanRetention %s want 1h", scanner.ScanRetention)
	}
}
