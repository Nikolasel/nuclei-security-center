package backend

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/scanner"
	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func contentSHA(yaml string) string {
	sum := sha256.Sum256([]byte(yaml))
	return hex.EncodeToString(sum[:])
}

// The backend builds a catalog bundle; the ACTUAL scanner-node verifier must
// accept it and report the same digest. This locks the two halves of the #85
// protocol together across package boundaries — a backend-side change to the tar
// layout or digest that the node would reject fails here, not in production.
func TestBuildCatalogBundleAcceptedByNode(t *testing.T) {
	bodies := []store.Template{
		{ID: "CVE-2021-44228", Path: "http/cves/2021/CVE-2021-44228.yaml", YAML: "id: CVE-2021-44228\ninfo:\n  name: Log4j\n  severity: critical\n", ContentSHA256: contentSHA("id: CVE-2021-44228\ninfo:\n  name: Log4j\n  severity: critical\n")},
		{ID: "my-custom", Path: "custom/my-custom.yaml", YAML: "id: my-custom\ninfo:\n  name: Mine\n  severity: low\n", ContentSHA256: contentSHA("id: my-custom\ninfo:\n  name: Mine\n  severity: low\n")},
	}
	data, digest, err := buildCatalogBundle(bodies)
	if err != nil {
		t.Fatalf("buildCatalogBundle: %v", err)
	}

	runner, err := scanner.NewRunner("/bin/echo", "/bin/echo", "connect", t.TempDir())
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	status, err := runner.ApplyBundle(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("node rejected backend-built bundle: %v", err)
	}
	if status.TemplatesCommit != digest {
		t.Errorf("node digest %q != builder digest %q", status.TemplatesCommit, digest)
	}
	if status.TemplateCount != len(bodies) {
		t.Errorf("count = %d, want %d", status.TemplateCount, len(bodies))
	}
	// The node now advertises the catalog digest — the distributor's staleness
	// check compares exactly this.
	if got := runner.Capabilities().TemplatesCommit; got != digest {
		t.Errorf("capabilities digest %q != %q", got, digest)
	}
}
