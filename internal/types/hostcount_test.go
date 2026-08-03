package types

import "testing"

// TestHostCount pins the accurate-expansion rule: a CIDR entry counts as its
// full address range, not as one array element. The prior behavior — plain
// len(hosts) — showed "1 host" for a target scoped to an entire /24 or larger.
func TestHostCount(t *testing.T) {
	cases := []struct {
		name  string
		hosts []string
		want  int64
	}{
		{"empty", nil, 0},
		{"single hostname", []string{"scanme.sh"}, 1},
		{"single IP", []string{"10.0.0.5"}, 1},
		{"URL form doesn't parse as CIDR", []string{"https://scanme.sh/path"}, 1},
		{"IPv4 /32 is one host", []string{"10.0.0.5/32"}, 1},
		{"IPv4 /24", []string{"10.0.0.0/24"}, 256},
		{"IPv4 /28", []string{"10.0.0.0/28"}, 16},
		{"IPv4 /0 is the whole address space", []string{"0.0.0.0/0"}, 4294967296},
		{"IPv6 /128 is one host", []string{"::1/128"}, 1},
		{
			"mixed entries sum",
			[]string{"scanme.sh", "10.0.0.0/24", "10.0.1.0/28", "10.0.2.5"},
			1 + 256 + 16 + 1,
		},
		{"garbage input counts as one, not zero", []string{"not a host!!"}, 1},
		{
			// Beyond int64 range (2^64) — must saturate, not wrap negative or
			// silently return 0 the way a naive uint64 shift-by->=64 would.
			"IPv6 /64 saturates at the int64 cap",
			[]string{"2001:db8::/64"},
			maxHostCount,
		},
		{
			"summing large entries also saturates, not overflows",
			[]string{"2001:db8::/64", "2001:db9::/64"},
			maxHostCount,
		},
		{
			"case-insensitive duplicate hostnames count once",
			[]string{"Example.COM", "example.com"},
			1,
		},
		{
			"duplicate CIDR entries count once",
			[]string{"10.0.0.0/24", "10.0.0.0/24"},
			256,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HostCount(c.hosts); got != c.want {
				t.Errorf("HostCount(%v) = %d, want %d", c.hosts, got, c.want)
			}
		})
	}
}
