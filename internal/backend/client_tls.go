package backend

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// mTLS for the backend→scanner path (#26). This upgrades the service auth from
// "bearer token over TLS" to mutual TLS: the backend presents a client
// certificate the node verifies, and (optionally) verifies the node's server
// certificate against a pinned CA. The bearer token stays — mTLS is additive
// (defense in depth), and in a service mesh the mesh can terminate mTLS instead,
// leaving these fields unset. Configuration is per node in the registry (#22):
// each node carries its own server CA / client cert / client key. Everything here
// is stdlib crypto/tls, no hand-rolled TLS (invariant #5).

// WithTLS returns a copy of the client whose requests use tlsCfg. A nil tlsCfg
// leaves the client unchanged (plain HTTP / default TLS).
func (c *ScannerClient) WithTLS(tlsCfg *tls.Config) *ScannerClient {
	if tlsCfg == nil {
		return c
	}
	out := *c
	out.tlsCfg = tlsCfg
	out.http = out.newHTTPClient(c.http.Timeout)
	return &out
}

// clientForNode builds a ScannerClient for a registered node, applying its
// per-node mTLS config when any TLS field is set. A node with no TLS fields gets
// a plain client (HTTP, or HTTPS against system roots if its endpoint is https).
func clientForNode(n store.ScannerNode) (*ScannerClient, error) {
	cfg, err := nodeTLSConfig(n)
	if err != nil {
		return nil, fmt.Errorf("scanner node %q TLS: %w", n.Name, err)
	}
	return NewScannerClient(n.Endpoint, n.Token).WithTLS(cfg), nil
}

// nodeTLSConfig builds a node's client-side TLS config from its stored PEM
// material, or returns (nil, nil) when none is configured. TLSClientCert +
// TLSClientKey are the cert the backend presents (both required together);
// TLSServerCA pins the node's server cert (optional — falls back to system roots).
func nodeTLSConfig(n store.ScannerNode) (*tls.Config, error) {
	if n.TLSServerCA == "" && n.TLSClientCert == "" && n.TLSClientKey == "" {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if n.TLSClientCert != "" || n.TLSClientKey != "" {
		if n.TLSClientCert == "" || n.TLSClientKey == "" {
			return nil, fmt.Errorf("client cert and key must be set together")
		}
		cert, err := tls.X509KeyPair([]byte(n.TLSClientCert), []byte(n.TLSClientKey))
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if n.TLSServerCA != "" {
		pool, err := certPoolFromPEM(n.TLSServerCA)
		if err != nil {
			return nil, fmt.Errorf("load server CA: %w", err)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// certPoolFromPEM parses a PEM CA bundle into a new cert pool.
func certPoolFromPEM(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, fmt.Errorf("no certificates found in PEM")
	}
	return pool, nil
}
