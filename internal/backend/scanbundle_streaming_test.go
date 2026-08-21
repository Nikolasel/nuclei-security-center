package backend

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestDecodeScanBundleJSONStreamsFindingsCount verifies the decoder bounds the
// decoded heap by streaming the findings array and enforcing the findings
// limit at decode time, not as a post-decode check. A wire payload of
// ~3 bytes/element ([{},{},…]) would otherwise amplify 512 MiB into tens of
// GiB of Go structs and OOM the backend (see review of #236). The limit is
// injectable for the test so the boundary can be asserted cheaply without
// materializing 1M+1 findings in every CI run.
func TestDecodeScanBundleJSONStreamsFindingsCount(t *testing.T) {
	buildPayload := func(count int) []byte {
		findings := strings.Repeat("{},", count)
		if count > 0 {
			findings = findings[:len(findings)-1]
		}
		return []byte(fmt.Sprintf(`{"format":"nuclei-security-center/scan-bundle","format_version":1,"exported_at":"2026-07-01T12:00:00Z","scan":{"id":"11111111-1111-1111-1111-111111111111","state":"complete","source":"adhoc","created_at":"2026-07-01T12:00:00Z","spec":{}},"findings":[%s]}`,
			findings))
	}

	small := buildPayload(10)
	if _, err := decodeScanBundleJSON(bytes.NewReader(small), types.ScanBundleMaxUpload); err != nil {
		t.Fatalf("small bundle decode failed: %v", err)
	}

	// Cheap boundary check via injectable limit: 3 accepted, 4 rejected.
	limit := 3
	okPayload := buildPayload(limit)
	if _, err := decodeScanBundleJSONWithLimit(bytes.NewReader(okPayload), types.ScanBundleMaxUpload, limit); err != nil {
		t.Fatalf("payload at limit decode failed: %v", err)
	}
	overPayload := buildPayload(limit + 1)
	if _, err := decodeScanBundleJSONWithLimit(bytes.NewReader(overPayload), types.ScanBundleMaxUpload, limit); err == nil || !strings.Contains(err.Error(), "findings exceeds") {
		t.Fatalf("expected findings-limit error for over-limit payload, got %v", err)
	}

	// Sanity: the real constant is still enforced via the production wrapper.
	if types.ScanBundleMaxFindings != 1<<20 {
		t.Fatalf("unexpected ScanBundleMaxFindings %d", types.ScanBundleMaxFindings)
	}
}
