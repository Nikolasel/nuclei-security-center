package backend

import (
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
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
		{"name":"corp","cidrs":["10.0.0.0/8"],"url":"http://corp:8081","token":"c","max_concurrent_scans":3},
		{"name":"dmz","cidrs":["192.168.1.0/24"],"url":"http://dmz:8081","token":"d"}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 { // default + corp + dmz
		t.Fatalf("want 3 nodes, got %d", len(nodes))
	}
	if nodes[1].MaxConcurrentScans != 3 || nodes[2].MaxConcurrentScans != types.DefaultMaxConcurrentScans {
		t.Fatalf("node capacities = %d/%d, want 3/%d", nodes[1].MaxConcurrentScans, nodes[2].MaxConcurrentScans, types.DefaultMaxConcurrentScans)
	}
}

func TestParseNodeConfigInvalid(t *testing.T) {
	cases := []struct {
		name, zones, wantErr string
	}{
		{"bad json", `not json`, "invalid JSON"},
		{"missing name", `[{"cidrs":["10.0.0.0/8"],"url":"http://u","token":"t"}]`, "missing a name"},
		{"reserved default name", `[{"name":"default","url":"http://u","token":"t"}]`, "reserved for SCANNER_URL"},
		{"missing url/token", `[{"name":"a","cidrs":["10.0.0.0/8"]}]`, "needs a url and token"},
		{"unsupported endpoint", `[{"name":"a","url":"ftp://scanner","token":"t"}]`, "endpoint must be an absolute http or https URL"},
		{"bad cidr", `[{"name":"a","cidrs":["nope"],"url":"http://u","token":"t"}]`, "bad CIDR"},
		{"dup name", `[{"name":"a","url":"http://u","token":"t"},{"name":"a","url":"http://u2","token":"t2"}]`, "duplicate zone name"},
		{"overlap identical", `[{"name":"a","cidrs":["10.0.0.0/8"],"url":"http://u","token":"t"},{"name":"b","cidrs":["10.0.0.0/8"],"url":"http://u2","token":"t2"}]`, "overlapping CIDRs"},
		{"overlap nested", `[{"name":"a","cidrs":["10.0.0.0/8"],"url":"http://u","token":"t"},{"name":"b","cidrs":["10.1.2.0/24"],"url":"http://u2","token":"t2"}]`, "overlapping CIDRs"},
		{"capacity below zero", `[{"name":"a","url":"http://u","token":"t","max_concurrent_scans":-1}]`, "max_concurrent_scans must be between 1 and 100"},
		{"capacity too high", `[{"name":"a","url":"http://u","token":"t","max_concurrent_scans":101}]`, "max_concurrent_scans must be between 1 and 100"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseNodeConfig("http://d", "t", c.zones)
			if err == nil {
				t.Fatalf("parseNodeConfig(%q) = nil error, want error containing %q", c.zones, c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("parseNodeConfig(%q) error = %q, want substring %q", c.zones, err, c.wantErr)
			}
		})
	}
}

func TestParseNodeConfigInvalidDefaultEndpoint(t *testing.T) {
	_, err := parseNodeConfig("scanner:8081", "t", "")
	if err == nil || !strings.Contains(err.Error(), "SCANNER_URL: endpoint must be an absolute http or https URL") {
		t.Fatalf("parseNodeConfig invalid default endpoint error = %v, want SCANNER_URL prefix", err)
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
				Name:               "node",
				Endpoint:           tc.endpoint,
				Token:              "token",
				MaxConcurrentScans: types.DefaultMaxConcurrentScans,
			}, true)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateNode(%q) error = %v, wantErr %t", tc.endpoint, err, tc.wantErr)
			}
		})
	}
}

func TestValidateNodeConcurrency(t *testing.T) {
	valid := store.ScannerNode{Name: "node", Endpoint: "http://scanner", Token: "token", MaxConcurrentScans: types.DefaultMaxConcurrentScans}
	if err := validateNode(&valid, true); err != nil {
		t.Fatalf("valid capacity rejected: %v", err)
	}

	for _, value := range []int{0, -1, types.MaxConcurrentScansCeiling + 1} {
		invalid := store.ScannerNode{Name: "node", Endpoint: "http://scanner", Token: "token", MaxConcurrentScans: value}
		if err := validateNode(&invalid, true); err == nil {
			t.Errorf("capacity %d accepted, want validation error", value)
		}
	}
}

func TestScannerNodeInputCapacityPresence(t *testing.T) {
	existingCapacity := 3
	omitted := scannerNodeInput{Name: "node", Endpoint: "http://scanner", Token: "token"}
	if got := omitted.storeNode(existingCapacity).MaxConcurrentScans; got != existingCapacity {
		t.Fatalf("omitted capacity = %d, want existing capacity %d", got, existingCapacity)
	}

	explicitZero := 0
	explicit := scannerNodeInput{
		Name:               "node",
		Endpoint:           "http://scanner",
		Token:              "token",
		MaxConcurrentScans: &explicitZero,
	}
	if got := explicit.storeNode(types.DefaultMaxConcurrentScans).MaxConcurrentScans; got != 0 {
		t.Fatalf("explicit zero capacity = %d, want 0 for validation to reject", got)
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
