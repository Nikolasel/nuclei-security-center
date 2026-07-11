package backend

import (
	"reflect"
	"testing"
)

func TestOutOfScopeHosts(t *testing.T) {
	approved := []string{
		"example.com",
		"https://app.example.com/login",
		"10.0.0.0/24",
		"192.168.1.5",
		"2001:db8::/32",
	}

	cases := []struct {
		name    string
		targets []string
		wantBad []string
	}{
		{"exact hostname", []string{"example.com"}, nil},
		{"hostname case-insensitive", []string{"EXAMPLE.com"}, nil},
		{"hostname with port ignored", []string{"example.com:8443"}, nil},
		{"url to approved host", []string{"https://example.com/whatever"}, nil},
		{"host from approved url", []string{"app.example.com"}, nil},
		{"subdomain not covered (no wildcard)", []string{"sub.example.com"}, []string{"sub.example.com"}},
		{"lookalike rejected", []string{"evil-example.com"}, []string{"evil-example.com"}},
		{"ip inside cidr", []string{"10.0.0.42"}, nil},
		{"ip inside cidr with port", []string{"10.0.0.42:443"}, nil},
		{"ip outside cidr", []string{"10.0.1.1"}, []string{"10.0.1.1"}},
		{"exact ip", []string{"192.168.1.5"}, nil},
		{"ipv6 inside cidr", []string{"2001:db8::1"}, nil},
		{"ipv6 outside cidr", []string{"2001:dead::1"}, []string{"2001:dead::1"}},
		{"cidr within approved cidr", []string{"10.0.0.0/28"}, nil},
		{"cidr broader than approved rejected", []string{"10.0.0.0/16"}, []string{"10.0.0.0/16"}},
		{"hostname can't match a cidr", []string{"host-in.10.0.0.0"}, []string{"host-in.10.0.0.0"}},
		{"mixed", []string{"example.com", "8.8.8.8"}, []string{"8.8.8.8"}},
		{"garbage fails closed", []string{"not a host"}, []string{"not a host"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := outOfScopeHosts(approved, c.targets)
			if !reflect.DeepEqual(got, c.wantBad) {
				t.Errorf("outOfScopeHosts(%v) = %v, want %v", c.targets, got, c.wantBad)
			}
		})
	}
}

func TestOutOfScopeHostsEmptyAllowlistRejectsAll(t *testing.T) {
	got := outOfScopeHosts(nil, []string{"example.com", "10.0.0.1"})
	want := []string{"example.com", "10.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("with no approved targets, got %v, want all rejected %v", got, want)
	}
}
