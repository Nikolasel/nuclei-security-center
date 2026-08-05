package backend

import (
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

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
		{"unsupported endpoint", `[{"name":"a","url":"ftp://scanner","token":"t"}]`},
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
		`[{"name":"a","cidrs":["10.0.0.0/8","10.1.2.0/24"],"url":"http://a","token":"t"}]`); err != nil {
		t.Errorf("within-node overlap should be allowed: %v", err)
	}
}

func TestValidateNodeEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{name: "http", endpoint: "http://scanner:8081"},
		{name: "https", endpoint: "https://scanner.example/v1"},
		{name: "missing scheme", endpoint: "scanner:8081", wantErr: true},
		{name: "unsupported scheme", endpoint: "ftp://scanner:21", wantErr: true},
		{name: "missing host", endpoint: "http:///v1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNode(&store.ScannerNode{
				Name:     "node",
				Endpoint: tc.endpoint,
				Token:    "token",
			}, true)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateNode(%q) error = %v, wantErr %t", tc.endpoint, err, tc.wantErr)
			}
		})
	}
}

func TestValidateNodeTLS(t *testing.T) {
	cert, key := selfSignedPEM(t)
	ca, _ := selfSignedPEM(t)

	t.Run("none is fine", func(t *testing.T) {
		if err := validateNodeTLS(&store.ScannerNode{}, true); err != nil {
			t.Fatalf("no TLS material should validate: %v", err)
		}
	})
	t.Run("valid pair + CA", func(t *testing.T) {
		in := &store.ScannerNode{TLSServerCA: ca, TLSClientCert: cert, TLSClientKey: key}
		if err := validateNodeTLS(in, true); err != nil {
			t.Fatalf("valid material should validate: %v", err)
		}
	})
	t.Run("create rejects half a keypair", func(t *testing.T) {
		if err := validateNodeTLS(&store.ScannerNode{TLSClientCert: cert}, true); err == nil {
			t.Fatal("cert without key on create should be rejected")
		}
	})
	t.Run("update allows cert-only (key kept)", func(t *testing.T) {
		if err := validateNodeTLS(&store.ScannerNode{TLSClientCert: cert}, false); err != nil {
			t.Fatalf("cert-only on update should be allowed: %v", err)
		}
	})
	t.Run("bad server CA rejected", func(t *testing.T) {
		if err := validateNodeTLS(&store.ScannerNode{TLSServerCA: "nope"}, true); err == nil {
			t.Fatal("garbage CA should be rejected")
		}
	})
	t.Run("mismatched pair rejected", func(t *testing.T) {
		_, otherKey := selfSignedPEM(t)
		if err := validateNodeTLS(&store.ScannerNode{TLSClientCert: cert, TLSClientKey: otherKey}, true); err == nil {
			t.Fatal("cert/key from different keypairs should be rejected")
		}
	})
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
