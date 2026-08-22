package backend

import (
	"encoding/json"
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
		{name: "credentials", endpoint: "http://user:pass@scanner:8081", wantErr: true},
		{name: "fragment", endpoint: "http://scanner:8081#frag", wantErr: true},
		{name: "localhost", endpoint: "http://localhost:8081", wantErr: true},
		{name: "loopback ipv4", endpoint: "http://127.0.0.1:8081", wantErr: true},
		{name: "loopback ipv6", endpoint: "http://[::1]:8081", wantErr: true},
		{name: "link-local", endpoint: "http://169.254.169.254/latest", wantErr: true},
		{name: "link-local ipv6", endpoint: "http://[fe80::1]:8081", wantErr: true},
		{name: "unspecified", endpoint: "http://0.0.0.0:8081", wantErr: true},
		{name: "private allowed", endpoint: "http://10.0.0.1:8081"},
		{name: "private allowed 2", endpoint: "http://192.168.1.10:8081"},
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

func TestValidateNodeTLSRequiresHTTPS(t *testing.T) {
	cert, key := selfSignedPEM(t)
	ca, _ := selfSignedPEM(t)

	cases := []struct {
		name    string
		node    store.ScannerNode
		wantErr bool
	}{
		{"http no tls ok", store.ScannerNode{Name: "n", Endpoint: "http://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans}, false},
		{"https no tls ok", store.ScannerNode{Name: "n", Endpoint: "https://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans}, false},
		{"https with ca ok", store.ScannerNode{Name: "n", Endpoint: "https://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans, TLSServerCA: ca}, false},
		{"https with cert+key ok", store.ScannerNode{Name: "n", Endpoint: "https://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans, TLSClientCert: cert, TLSClientKey: key}, false},
		{"https with all tls ok", store.ScannerNode{Name: "n", Endpoint: "https://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans, TLSServerCA: ca, TLSClientCert: cert, TLSClientKey: key}, false},
		{"http with ca rejected", store.ScannerNode{Name: "n", Endpoint: "http://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans, TLSServerCA: ca}, true},
		{"http with cert+key rejected", store.ScannerNode{Name: "n", Endpoint: "http://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans, TLSClientCert: cert, TLSClientKey: key}, true},
		{"http with cert only rejected", store.ScannerNode{Name: "n", Endpoint: "http://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans, TLSClientCert: cert}, true},
		{"http with key only rejected", store.ScannerNode{Name: "n", Endpoint: "http://scanner:8081", Token: "tok", MaxConcurrentScans: types.DefaultMaxConcurrentScans, TLSClientKey: key}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNode(&tc.node, true)
			if tc.wantErr && err == nil {
				t.Fatalf("validateNode should have failed for %q", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateNode unexpectedly failed for %q: %v", tc.name, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "https") {
				t.Fatalf("error %q should mention https, got %q", tc.name, err.Error())
			}
		})
	}
}

func TestParseNodeConfigTLSRequiresHTTPS(t *testing.T) {
	cert, key := selfSignedPEM(t)
	ca, _ := selfSignedPEM(t)

	zonesCA, _ := json.Marshal([]ScanZoneConfig{{Name: "a", URL: "http://a:8081", Token: "t", TLSServerCA: ca}})
	if _, err := parseNodeConfig("https://d:8081", "tok", string(zonesCA)); err == nil {
		t.Fatal("parseNodeConfig http+CA should be rejected")
	} else if !strings.Contains(err.Error(), "https") {
		t.Fatalf("want https error, got %v", err)
	}

	zonesCert, _ := json.Marshal([]ScanZoneConfig{{Name: "a", URL: "http://a:8081", Token: "t", TLSClientCert: cert, TLSClientKey: key}})
	if _, err := parseNodeConfig("https://d:8081", "tok", string(zonesCert)); err == nil {
		t.Fatal("parseNodeConfig http+cert should be rejected")
	} else if !strings.Contains(err.Error(), "https") {
		t.Fatalf("want https error, got %v", err)
	}

	zonesOK, _ := json.Marshal([]ScanZoneConfig{{Name: "a", URL: "https://a:8081", Token: "t", TLSServerCA: ca}})
	if _, err := parseNodeConfig("https://d:8081", "tok", string(zonesOK)); err != nil {
		t.Fatalf("https+CA should be accepted, got %v", err)
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
