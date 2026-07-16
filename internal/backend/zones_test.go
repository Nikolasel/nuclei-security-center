package backend

import "testing"

func TestBuildDispatcherDefaultOnly(t *testing.T) {
	d, err := BuildDispatcher("", "http://scanner:8081", "tok")
	if err != nil {
		t.Fatal(err)
	}
	// With no zones, every target routes to the default zone.
	_, name, err := d.ClientFor([]string{"10.0.0.5", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "default" {
		t.Errorf("zone = %q, want default", name)
	}
}

func TestBuildDispatcherInvalid(t *testing.T) {
	cases := []string{
		`not json`,
		`[{"cidrs":["10.0.0.0/8"],"url":"u","token":"t"}]`,                          // no name
		`[{"name":"a","cidrs":["10.0.0.0/8"]}]`,                                     // no url/token
		`[{"name":"a","cidrs":["nope"],"url":"u","token":"t"}]`,                     // bad cidr
		`[{"name":"a","url":"u","token":"t"},{"name":"a","url":"u2","token":"t2"}]`, // dup name
		// overlapping CIDRs across zones (identical block)
		`[{"name":"a","cidrs":["10.0.0.0/8"],"url":"u","token":"t"},{"name":"b","cidrs":["10.0.0.0/8"],"url":"u2","token":"t2"}]`,
		// overlapping CIDRs across zones (one nested in the other)
		`[{"name":"a","cidrs":["10.0.0.0/8"],"url":"u","token":"t"},{"name":"b","cidrs":["10.1.2.0/24"],"url":"u2","token":"t2"}]`,
	}
	for _, c := range cases {
		if _, err := BuildDispatcher(c, "http://d", "t"); err == nil {
			t.Errorf("BuildDispatcher(%q) = nil error, want error", c)
		}
	}
}

func TestBuildDispatcherWithinZoneOverlapAllowed(t *testing.T) {
	// Overlapping CIDRs inside a single zone are harmless (same node, no
	// ambiguity) — only cross-zone overlaps are rejected.
	if _, err := BuildDispatcher(
		`[{"name":"a","cidrs":["10.0.0.0/8","10.1.2.0/24"],"url":"u","token":"t"}]`,
		"http://d", "t"); err != nil {
		t.Errorf("within-zone overlap should be allowed: %v", err)
	}
}

func newTestDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	d, err := BuildDispatcher(`[
		{"name":"corp","cidrs":["10.0.0.0/8"],"url":"http://corp:8081","token":"c"},
		{"name":"dmz","cidrs":["192.168.1.0/24"],"url":"http://dmz:8081","token":"d"}
	]`, "http://default:8081", "def")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestClientForZoneMatch(t *testing.T) {
	d := newTestDispatcher(t)
	cases := []struct {
		name    string
		targets []string
		want    string
	}{
		{"corp ip", []string{"10.1.2.3"}, "corp"},
		{"corp cidr", []string{"10.9.0.0/16"}, "corp"},
		{"dmz ip:port", []string{"192.168.1.20:8443"}, "dmz"},
		{"dmz url", []string{"https://192.168.1.5/login"}, "dmz"},
		{"hostname → default", []string{"scanme.example.com"}, "default"},
		{"outside all zones → default", []string{"8.8.8.8"}, "default"},
		{"hostname alongside a zoned ip uses the zone", []string{"10.0.0.1", "host.example"}, "corp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, name, err := d.ClientFor(c.targets)
			if err != nil {
				t.Fatalf("ClientFor(%v): %v", c.targets, err)
			}
			if name != c.want {
				t.Errorf("ClientFor(%v) zone = %q, want %q", c.targets, name, c.want)
			}
		})
	}
}

func TestClientForSpanningZonesRejected(t *testing.T) {
	d := newTestDispatcher(t)
	if _, _, err := d.ClientFor([]string{"10.0.0.1", "192.168.1.1"}); err == nil {
		t.Fatal("a scan spanning corp and dmz should be rejected")
	}
}

func TestClientForSameZoneMultipleTargets(t *testing.T) {
	d := newTestDispatcher(t)
	_, name, err := d.ClientFor([]string{"10.0.0.1", "10.5.5.5", "10.9.9.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "corp" {
		t.Errorf("zone = %q, want corp", name)
	}
}
