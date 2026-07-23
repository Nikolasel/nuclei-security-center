package templates

import (
	"errors"
	"testing"
)

func TestParseExtractsMetadataWithoutChangingYAML(t *testing.T) {
	body := []byte("# preserved comment\nid: example-template\ninfo:\n  name: Example\n  author: [alice, bob]\n  severity: HIGH\n  description: Example description\n  tags: web, cve, web\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n")
	got, err := Parse("http/example.yaml", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.ID != "example-template" || got.Name != "Example" || got.Author != "alice, bob" || got.Severity != "high" {
		t.Errorf("unexpected metadata: %+v", got)
	}
	if got.YAML != string(body) {
		t.Fatal("YAML was not retained byte-for-byte")
	}
	if want := []string{"cve", "web"}; len(got.Tags) != len(want) || got.Tags[0] != want[0] || got.Tags[1] != want[1] {
		t.Errorf("tags = %v, want %v", got.Tags, want)
	}
	if got.ContentSHA256 == "" {
		t.Error("expected content sha256")
	}
}

func TestParseRecognizesNonTemplates(t *testing.T) {
	_, err := Parse(".github/workflow.yml", []byte("name: CI\non: push\n"))
	if !errors.Is(err, ErrNotTemplate) {
		t.Fatalf("Parse error = %v, want ErrNotTemplate", err)
	}
}

func TestParseRejectsMalformedTemplate(t *testing.T) {
	_, err := Parse("http/bad.yaml", []byte("id: bad\ninfo:\n  severity: high\n"))
	if err == nil {
		t.Fatal("expected missing info.name error")
	}
}
