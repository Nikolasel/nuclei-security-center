package backend

import (
	"context"
	"strings"
	"testing"
)

func TestBuildScanSpecRequiresPolicyAndTarget(t *testing.T) {
	var server Server
	for _, tc := range []struct {
		name string
		req  createScanRequest
		want string
	}{
		{name: "missing policy", req: createScanRequest{TargetID: "target"}, want: "scan_policy_id is required"},
		{name: "missing target", req: createScanRequest{ScanPolicyID: "policy"}, want: "target_id is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := server.buildScanSpec(context.Background(), tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("buildScanSpec(%+v) error = %v, want %q", tc.req, err, tc.want)
			}
		})
	}
}
