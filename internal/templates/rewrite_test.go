package templates

import (
	"strings"
	"testing"
)

func TestRewriteIDPreservesTemplateSemantics(t *testing.T) {
	body := []byte(`# retained comment
id: old-id
info:
  name: Example
  severity: low
http:
  - method: GET
    path: ["{{BaseURL}}"]
`)
	rewritten, err := RewriteID(body, "new-id")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rewritten), "# retained comment") {
		t.Errorf("comment was not retained:\n%s", rewritten)
	}
	meta, err := ParseCustom("custom/new-id.yaml", rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID != "new-id" || meta.Name != "Example" {
		t.Fatalf("unexpected rewritten metadata: %+v", meta)
	}
}
