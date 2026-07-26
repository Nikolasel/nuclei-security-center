package types

import (
	"encoding/json"
	"testing"
	"time"
)

// A representative Nuclei JSONL result line (fields as emitted by `nuclei -jsonl`).
const sampleLine = `{"template-id":"tech-detect","template-path":"http/technologies/tech-detect.yaml","info":{"name":"Wappalyzer Technology Detection","author":["hakluke"],"tags":["tech"],"description":"Detection","severity":"info"},"type":"http","host":"https://scanme.sh","matched-at":"https://scanme.sh","ip":"128.199.158.128","timestamp":"2024-01-01T12:00:00.123456+00:00","matcher-status":true}`

func TestNucleiFindingParse(t *testing.T) {
	var f NucleiFinding
	if err := json.Unmarshal([]byte(sampleLine), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cases := map[string]struct{ got, want string }{
		"template-id": {f.TemplateID, "tech-detect"},
		"type":        {f.Type, "http"},
		"host":        {f.Host, "https://scanme.sh"},
		"matched-at":  {f.MatchedAt, "https://scanme.sh"},
		"info.name":   {f.Info.Name, "Wappalyzer Technology Detection"},
		"severity":    {f.Info.Severity, "info"},
	}
	for field, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", field, c.got, c.want)
		}
	}
	if f.Timestamp == "" {
		t.Error("timestamp not parsed")
	}
}

func TestNewIDFormat(t *testing.T) {
	id := NewID()
	if len(id) != 36 {
		t.Fatalf("id length = %d, want 36 (%q)", len(id), id)
	}
	if id[14] != '4' {
		t.Errorf("version nibble = %c, want 4 (%q)", id[14], id)
	}
	if NewID() == NewID() {
		t.Error("NewID returned duplicate values")
	}
}

func TestBundleDigestOrderIndependent(t *testing.T) {
	a := []TemplateBundleEntry{
		{ID: "b", Path: "http/b.yaml", SHA256: "22"},
		{ID: "a", Path: "http/a.yaml", SHA256: "11"},
	}
	b := []TemplateBundleEntry{
		{ID: "a", Path: "different/a.yaml", SHA256: "11"},
		{ID: "b", Path: "http/b.yaml", SHA256: "22"},
	}
	// Same ids+hashes in a different order (and a different path for a) → same
	// digest: the digest is content-addressed over sorted id\x00sha256 lines.
	if BundleDigest(a) != BundleDigest(b) {
		t.Errorf("digest should be order- and path-independent")
	}
	// A changed hash changes the digest.
	c := []TemplateBundleEntry{{ID: "a", SHA256: "11"}, {ID: "b", SHA256: "99"}}
	if BundleDigest(a) == BundleDigest(c) {
		t.Errorf("digest should change when a content hash changes")
	}
	if BundleDigest(nil) == "" {
		t.Errorf("digest of empty set should still be a valid sha256 hex, got empty")
	}
}

func TestTemplateBatchValidationTimeoutLayering(t *testing.T) {
	if TemplateBatchValidationNodeTimeout >= TemplateBatchValidationClientTimeout {
		t.Fatalf(
			"node timeout %s must be shorter than client timeout %s",
			TemplateBatchValidationNodeTimeout,
			TemplateBatchValidationClientTimeout,
		)
	}
	fullAttempts := time.Duration(TemplateBatchValidationMaxAttempts) * TemplateBatchValidationClientTimeout
	if TemplateBatchValidationRequestTimeout <= fullAttempts {
		t.Fatalf(
			"request timeout %s must permit %d complete client attempts (%s)",
			TemplateBatchValidationRequestTimeout,
			TemplateBatchValidationMaxAttempts,
			fullAttempts,
		)
	}
}
