package types

import (
	"slices"
	"testing"
)

func TestNormalizeTargetHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "hostname", in: " Example.COM ", want: "example.com"},
		{name: "hostname with port", in: "Example.COM:8443", want: "example.com:8443"},
		{name: "URL host only", in: "HTTPS://EXAMPLE.com/AdminPanel", want: "https://example.com/AdminPanel"},
		{name: "IP unchanged", in: "10.0.0.1", want: "10.0.0.1"},
		{name: "CIDR unchanged", in: "2001:DB8::/64", want: "2001:DB8::/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeTargetHost(tc.in); got != tc.want {
				t.Errorf("NormalizeTargetHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDeduplicateTargetHostsPreservesOrder(t *testing.T) {
	got := DeduplicateTargetHosts([]string{
		"Example.COM",
		"example.com",
		"https://EXAMPLE.com/AdminPanel",
		"https://example.com/AdminPanel",
		"https://example.com/adminpanel",
		"10.0.0.0/24",
		"10.0.0.0/24",
	})
	want := []string{
		"example.com",
		"https://example.com/AdminPanel",
		"https://example.com/adminpanel",
		"10.0.0.0/24",
	}
	if !slices.Equal(got, want) {
		t.Errorf("DeduplicateTargetHosts = %v, want %v", got, want)
	}
}
