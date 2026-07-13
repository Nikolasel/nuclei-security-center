package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Server-side TLS / mTLS for the scanner node (#26). When placed in an untrusted
// network segment, a node should accept dispatch only over a mutually
// authenticated connection. ServerTLSFromEnv builds that config; the bearer
// token check stays in place regardless (mTLS is additive). Pure stdlib
// crypto/tls — no hand-rolled TLS (invariant #5).

// ServerTLSFromEnv builds the node's server TLS config, or (nil, nil) when no
// server certificate is configured (plain HTTP, as before). It reads:
//
//   - SCANNER_TLS_CERT / SCANNER_TLS_KEY — the node's server certificate
//     (both required together to serve HTTPS).
//   - SCANNER_CLIENT_CA — a PEM CA bundle; when set, the node **requires and
//     verifies** a client certificate (mTLS), so a client without a valid cert
//     is rejected at the TLS handshake.
func ServerTLSFromEnv() (*tls.Config, error) {
	certFile := os.Getenv("SCANNER_TLS_CERT")
	keyFile := os.Getenv("SCANNER_TLS_KEY")
	clientCA := os.Getenv("SCANNER_CLIENT_CA")
	if certFile == "" && keyFile == "" && clientCA == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("SCANNER_TLS_CERT and SCANNER_TLS_KEY are required to serve TLS")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load scanner server cert: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if clientCA != "" {
		pool, err := loadCertPool(clientCA)
		if err != nil {
			return nil, fmt.Errorf("load client CA: %w", err)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// RequiresClientCert reports whether cfg enforces mTLS (a verified client cert).
func RequiresClientCert(cfg *tls.Config) bool {
	return cfg != nil && cfg.ClientAuth == tls.RequireAndVerifyClientCert
}

func loadCertPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %q", file)
	}
	return pool, nil
}
