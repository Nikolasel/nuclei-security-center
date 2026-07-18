package backend

import "testing"

func TestParseNodeConfigDefaultOnly(t *testing.T) {
	nodes, err := parseNodeConfig("http://scanner:8081", "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "default" || len(nodes[0].CIDRs) != 0 {
		t.Fatalf("want a single catch-all 'default' node, got %+v", nodes)
	}
}

func TestParseNodeConfigValid(t *testing.T) {
	nodes, err := parseNodeConfig("http://d", "t", `[
		{"name":"corp","cidrs":["10.0.0.0/8"],"url":"http://corp:8081","token":"c"},
		{"name":"dmz","cidrs":["192.168.1.0/24"],"url":"http://dmz:8081","token":"d"}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 { // default + corp + dmz
		t.Fatalf("want 3 nodes, got %d", len(nodes))
	}
}

func TestParseNodeConfigInvalid(t *testing.T) {
	cases := []struct {
		name, zones string
	}{
		{"bad json", `not json`},
		{"missing name", `[{"cidrs":["10.0.0.0/8"],"url":"u","token":"t"}]`},
		{"reserved default name", `[{"name":"default","url":"u","token":"t"}]`},
		{"missing url/token", `[{"name":"a","cidrs":["10.0.0.0/8"]}]`},
		{"bad cidr", `[{"name":"a","cidrs":["nope"],"url":"u","token":"t"}]`},
		{"dup name", `[{"name":"a","url":"u","token":"t"},{"name":"a","url":"u2","token":"t2"}]`},
		{"overlap identical", `[{"name":"a","cidrs":["10.0.0.0/8"],"url":"u","token":"t"},{"name":"b","cidrs":["10.0.0.0/8"],"url":"u2","token":"t2"}]`},
		{"overlap nested", `[{"name":"a","cidrs":["10.0.0.0/8"],"url":"u","token":"t"},{"name":"b","cidrs":["10.1.2.0/24"],"url":"u2","token":"t2"}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseNodeConfig("http://d", "t", c.zones); err == nil {
				t.Errorf("parseNodeConfig(%q) = nil error, want error", c.zones)
			}
		})
	}
}

func TestParseNodeConfigWithinNodeOverlapAllowed(t *testing.T) {
	// Overlapping CIDRs inside one node are harmless (same node, no ambiguity).
	if _, err := parseNodeConfig("http://d", "t",
		`[{"name":"a","cidrs":["10.0.0.0/8","10.1.2.0/24"],"url":"u","token":"t"}]`); err != nil {
		t.Errorf("within-node overlap should be allowed: %v", err)
	}
}

func TestSameStringSet(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"10.0.0.0/8"}, []string{"10.0.0.0/8"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, true}, // order-insensitive
		{[]string{}, []string{}, true},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a"}, []string{"b"}, false},
	}
	for _, c := range cases {
		if got := sameStringSet(c.a, c.b); got != c.want {
			t.Errorf("sameStringSet(%v,%v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
