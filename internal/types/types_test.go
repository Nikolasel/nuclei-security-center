package types

import (
	"encoding/json"
	"testing"
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
