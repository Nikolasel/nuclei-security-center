package backend

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
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

	runner, err := scanner.NewRunner("/bin/echo", "/bin/echo", "connect", t.TempDir(), 1)
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

// #213: the catalog's UNIQUE (source, path) constraint permits an upstream
// template and a custom template to claim one bundle-relative path (upstream
// tree containing custom/x.yaml alongside custom template id x). Packing must
// fail loudly here — not emit two same-named tar members, which the node would
// truncate and then reject wholesale, freezing distribution to every node.
func TestBuildCatalogBundleRejectsCrossSourcePathCollision(t *testing.T) {
	upstreamYAML := "id: x-upstream\ninfo:\n  name: From upstream\n  severity: medium\n"
	customYAML := "id: x\ninfo:\n  name: Custom lookalike\n  severity: low\n"
	bodies := []store.Template{
		{ID: "x-upstream", Source: "upstream", Path: "custom/x.yaml", YAML: upstreamYAML, ContentSHA256: contentSHA(upstreamYAML)},
		{ID: "x", Source: "custom", Path: "custom/x.yaml", YAML: customYAML, ContentSHA256: contentSHA(customYAML)},
	}
	data, digest, err := buildCatalogBundle(bodies)
	if !errors.Is(err, errDuplicateBundlePath) {
		t.Fatalf("err = %v, want errDuplicateBundlePath", err)
	}
	for _, want := range []string{"x-upstream", `"x"`, "custom/x.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name colliding artifact %q", err, want)
		}
	}
	if data != nil || digest != "" {
		t.Errorf("a rejected catalog must produce no bundle (data %d bytes, digest %q)", len(data), digest)
	}
}

// The packing invariant holds against non-identical spellings too: the node
// resolves member names through path cleaning, so "./"-prefixed and
// double-slash variants of one path must count as a collision rather than
// slipping past plain string equality. A literal backslash is NOT such an
// alias — see TestBuildCatalogBundleBackslashPathsAreDistinctMembers.
func TestBuildCatalogBundleRejectsAliasedPathCollision(t *testing.T) {
	yaml := "id: a\ninfo:\n  name: Dup\n  severity: high\n"
	for _, alias := range []string{"http/./a.yaml", "http//a.yaml"} {
		bodies := []store.Template{
			{ID: "one", Source: "upstream", Path: alias, YAML: yaml, ContentSHA256: contentSHA(yaml)},
			{ID: "two", Source: "custom", Path: "http/a.yaml", YAML: yaml, ContentSHA256: contentSHA(yaml)},
		}
		data, digest, err := buildCatalogBundle(bodies)
		if !errors.Is(err, errDuplicateBundlePath) {
			t.Fatalf("path %q: err = %v, want errDuplicateBundlePath", alias, err)
		}
		if data != nil || digest != "" {
			t.Errorf("path %q: rejected catalog produced a bundle", alias)
		}
	}
}

// The duplicate-name contract must be IDENTICAL on both sides of a push: the
// builder's dedup key and the extractor's resolved-member key. On the Linux
// scanner, filepath.ToSlash leaves a backslash as an ordinary filename
// character, so `http\a.yaml` and `http/a.yaml` extract as two distinct files
// and verify independently — packing this catalog must therefore succeed, and
// the node must accept both members (the pre-fix builder pre-replaced
// backslashes and falsely rejected it, aborting every push of a valid catalog).
func TestBuildCatalogBundleBackslashPathsAreDistinctMembers(t *testing.T) {
	fwdYAML := "id: fwd\ninfo:\n  name: Forward slash\n  severity: low\n"
	backYAML := "id: back\ninfo:\n  name: Literal backslash\n  severity: medium\n"
	bodies := []store.Template{
		{ID: "fwd", Source: "upstream", Path: "http/a.yaml", YAML: fwdYAML, ContentSHA256: contentSHA(fwdYAML)},
		{ID: "back", Source: "upstream", Path: `http\a.yaml`, YAML: backYAML, ContentSHA256: contentSHA(backYAML)},
	}
	data, digest, err := buildCatalogBundle(bodies)
	if err != nil {
		t.Fatalf("buildCatalogBundle: %v", err)
	}

	runner, err := scanner.NewRunner("/bin/echo", "/bin/echo", "connect", t.TempDir(), 1)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	status, err := runner.ApplyBundle(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("node rejected bundle with distinct backslash member: %v", err)
	}
	if status.TemplatesCommit != digest || status.TemplateCount != len(bodies) {
		t.Errorf("status = %+v, want commit %q count %d", status, digest, len(bodies))
	}
}
