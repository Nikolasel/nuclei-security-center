package store

import (
	"errors"
	"testing"
)

func testNodes() []ScannerNode {
	return []ScannerNode{
		{ID: "1", Name: "default", CIDRs: []string{}},
		{ID: "2", Name: "corp", CIDRs: []string{"10.0.0.0/8"}},
		{ID: "3", Name: "dmz", CIDRs: []string{"192.168.1.0/24"}},
	}
}

func TestSelectNode(t *testing.T) {
	nodes := testNodes()
	cases := []struct {
		name    string
		targets []string
		want    string // node name, or "" if an error is expected
	}{
		{"corp ip", []string{"10.1.2.3"}, "corp"},
		{"corp cidr", []string{"10.9.0.0/16"}, "corp"},
		{"dmz ip:port", []string{"192.168.1.20:8443"}, "dmz"},
		{"dmz url", []string{"https://192.168.1.5/login"}, "dmz"},
		{"hostname → catch-all", []string{"scanme.example.com"}, "default"},
		{"unmatched ip → catch-all", []string{"8.8.8.8"}, "default"},
		{"hostname rides the zoned ip", []string{"10.0.0.1", "host.example"}, "corp"},
		{"same node, many targets", []string{"10.0.0.1", "10.5.5.5", "10.9.9.0/24"}, "corp"},
		{"spanning nodes rejected", []string{"10.0.0.1", "192.168.1.1"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := selectNode(nodes, c.targets)
			if c.want == "" {
				if err == nil {
					t.Fatalf("selectNode(%v) = %q, want error", c.targets, n.Name)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectNode(%v): %v", c.targets, err)
			}
			if n.Name != c.want {
				t.Errorf("selectNode(%v) = %q, want %q", c.targets, n.Name, c.want)
			}
		})
	}
}

func TestSelectNodeNoCatchAll(t *testing.T) {
	// Only a zoned node exists; a hostname target has nowhere to go.
	nodes := []ScannerNode{{ID: "2", Name: "corp", CIDRs: []string{"10.0.0.0/8"}}}
	if _, err := selectNode(nodes, []string{"host.example"}); !errors.Is(err, ErrNoNodeForTarget) {
		t.Fatalf("want ErrNoNodeForTarget, got %v", err)
	}
	// An unmatched IP likewise has no catch-all.
	if _, err := selectNode(nodes, []string{"8.8.8.8"}); !errors.Is(err, ErrNoNodeForTarget) {
		t.Fatalf("want ErrNoNodeForTarget, got %v", err)
	}
}
