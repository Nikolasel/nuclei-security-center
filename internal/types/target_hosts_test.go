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
		{name: "empty port", in: "Example.COM:", want: "example.com"},
		{name: "URL host only", in: "HTTPS://EXAMPLE.com/AdminPanel", want: "https://example.com/AdminPanel"},
		{name: "IP unchanged", in: "10.0.0.1", want: "10.0.0.1"},
		{name: "mapped IPv4 address", in: "::ffff:10.0.0.1", want: "10.0.0.1"},
		{name: "mapped IPv4 address with port", in: "[::ffff:10.0.0.1]:80", want: "10.0.0.1:80"},
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
		"2001:DB8::/120",
		"2001:db8::/120",
		"2001:DB8::1",
		"2001:db8::1",
		"::1",
		"0:0:0:0:0:0:0:1",
		"[2001:DB8::1]:8080",
		"[2001:db8::1]:8080",
		"::ffff:10.0.0.1",
		"10.0.0.1",
		"[::ffff:10.0.0.1]:80",
		"10.0.0.1:80",
	})
	want := []string{
		"example.com",
		"https://example.com/AdminPanel",
		"https://example.com/adminpanel",
		"10.0.0.0/24",
		"2001:DB8::/120",
		"2001:DB8::1",
		"::1",
		"[2001:DB8::1]:8080",
		"10.0.0.1",
		"10.0.0.1:80",
	}
	if !slices.Equal(got, want) {
		t.Errorf("DeduplicateTargetHosts = %v, want %v", got, want)
	}
}

func TestDeduplicateTargetHostsKeepsDistinctURLRequestIdentity(t *testing.T) {
	got := DeduplicateTargetHosts([]string{
		"HTTPS://User:Pass@EXAMPLE.com:8443/Path",
		"https://user:Pass@example.com:8443/Path",
		"https://example.com:8443/Path",
		"https://example.com/Path",
	})
	want := []string{
		"https://User:Pass@example.com:8443/Path",
		"https://user:Pass@example.com:8443/Path",
		"https://example.com:8443/Path",
		"https://example.com/Path",
	}
	if !slices.Equal(got, want) {
		t.Errorf("URL target identity = %v, want %v", got, want)
	}
}
