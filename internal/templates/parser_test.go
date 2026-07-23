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

func TestParseCustomAcceptsValidTemplate(t *testing.T) {
	body := []byte("id: my-check\ninfo:\n  name: My Check\n  severity: medium\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n")
	got, err := ParseCustom("custom/my-check.yaml", body)
	if err != nil {
		t.Fatalf("ParseCustom: %v", err)
	}
	if got.ID != "my-check" || got.Severity != "medium" {
		t.Errorf("unexpected metadata: %+v", got)
	}
}

// Workflow files have no protocol block but a top-level workflows: list — still
// a valid executable document, so ParseCustom must accept them.
func TestParseCustomAcceptsWorkflow(t *testing.T) {
	body := []byte("id: my-flow\ninfo:\n  name: My Flow\n  severity: info\nworkflows:\n  - template: http/a.yaml\n")
	if _, err := ParseCustom("custom/my-flow.yaml", body); err != nil {
		t.Fatalf("ParseCustom workflow: %v", err)
	}
}

func TestParseCustomStricterThanParse(t *testing.T) {
	cases := map[string]string{
		"no executable section": "id: inert\ninfo:\n  name: X\n  severity: low\n",
		"unknown severity":      "id: typo\ninfo:\n  name: X\n  severity: hihg\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			// Lenient Parse accepts it (upstream is authoritative)...
			if _, err := Parse("http/x.yaml", []byte(body)); err != nil {
				t.Fatalf("Parse should accept upstream-style: %v", err)
			}
			// ...but ParseCustom rejects it as an authoring mistake.
			if _, err := ParseCustom("custom/x.yaml", []byte(body)); err == nil {
				t.Fatalf("ParseCustom should reject %q", name)
			}
		})
	}
}
