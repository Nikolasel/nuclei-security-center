package types

import "testing"

func TestHostKey(t *testing.T) {
	cases := map[string]string{
		"":                                      "",
		" Example.COM. ":                        "example.com",
		"example.com:8443":                      "example.com",
		"example.com:8443/admin?q=1":            "example.com",
		"https://User:pass@Example.COM:443/a#b": "example.com",
		"[2001:0db8::1]:443":                    "2001:db8::1",
		"https://[2001:db8::1]:8443/path":       "2001:db8::1",
		"2001:0db8::1":                          "2001:db8::1",
		"192.0.2.10:80":                         "192.0.2.10",
	}
	for input, want := range cases {
		if got := HostKey(input); got != want {
			t.Errorf("HostKey(%q) = %q, want %q", input, got, want)
		}
	}
}
