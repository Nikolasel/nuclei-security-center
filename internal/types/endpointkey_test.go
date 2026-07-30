package types

import "testing"

func TestEndpointKey(t *testing.T) {
	cases := map[string]string{
		"":                                      "",
		" Example.COM. ":                        "",
		"example.com:8443":                      "example.com:8443",
		"example.com:8443/admin?q=1":            "example.com:8443",
		"https://User:pass@Example.COM:443/a#b": "example.com:443",
		"https://example.com/path":              "example.com:443",
		"http://example.com/path":               "example.com:80",
		"[2001:0db8::1]:443":                    "[2001:db8::1]:443",
		"https://[2001:db8::1]:8443/path":       "[2001:db8::1]:8443",
		"2001:0db8::1":                          "",
		"192.0.2.10:80":                         "192.0.2.10:80",
		"example.com:abc":                       "",
	}
	for input, want := range cases {
		if got := EndpointKey(input, ""); got != want {
			t.Errorf("EndpointKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEndpointKeyProtocolDefaults(t *testing.T) {
	for _, tc := range []struct {
		input, protocol, want string
	}{
		{"example.com", "ssl", "example.com:443"},
		{"example.com", "dns", "example.com:53"},
		{"2001:db8::1", "ssl", "[2001:db8::1]:443"},
		{"example.com", "http", ""},
	} {
		if got := EndpointKey(tc.input, tc.protocol); got != tc.want {
			t.Errorf("EndpointKey(%q, %q) = %q, want %q", tc.input, tc.protocol, got, tc.want)
		}
	}
}
