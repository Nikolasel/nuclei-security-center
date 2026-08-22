package backend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// selfSignedPEM returns a self-signed cert + its private key, both PEM-encoded —
// the in-memory shape node TLS material takes in the registry.
func selfSignedPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestNodeTLSConfigDisabled(t *testing.T) {
	cfg, err := nodeTLSConfig(store.ScannerNode{Name: "n"})
	if err != nil || cfg != nil {
		t.Fatalf("nodeTLSConfig(no TLS) = (%v, %v), want (nil, nil)", cfg, err)
	}
}

func TestNodeTLSConfigClientCert(t *testing.T) {
	cert, key := selfSignedPEM(t)
	cfg, err := nodeTLSConfig(store.ScannerNode{TLSClientCert: cert, TLSClientKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatal("expected the client certificate to be loaded")
	}
}

func TestNodeTLSConfigServerCA(t *testing.T) {
	ca, _ := selfSignedPEM(t)
	cfg, err := nodeTLSConfig(store.ScannerNode{TLSServerCA: ca})
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("expected the server CA pool to be set")
	}
}

func TestNodeTLSConfigCertWithoutKey(t *testing.T) {
	cert, _ := selfSignedPEM(t)
	if _, err := nodeTLSConfig(store.ScannerNode{TLSClientCert: cert}); err == nil {
		t.Fatal("client cert without key should error")
	}
}

func TestNodeTLSConfigBadPEM(t *testing.T) {
	if _, err := nodeTLSConfig(store.ScannerNode{TLSServerCA: "not a pem"}); err == nil {
		t.Fatal("garbage server CA should error")
	}
}

func TestClientForNodeAppliesTLS(t *testing.T) {
	cert, key := selfSignedPEM(t)
	c, err := clientForNode(store.ScannerNode{
		Name: "corp", Endpoint: "https://scanner-corp:8081", Token: "tok",
		TLSClientCert: cert, TLSClientKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.tlsCfg == nil {
		t.Fatal("expected mTLS config to be applied to the client")
	}
	// A plain node yields a client with no TLS config.
	plain, err := clientForNode(store.ScannerNode{Name: "d", Endpoint: "http://scanner:8081", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if plain.tlsCfg != nil {
		t.Error("a node without TLS material should have no TLS config")
	}
}

func TestNodeTLSConfigRequiresHTTPS(t *testing.T) {
	cert, key := selfSignedPEM(t)
	ca, _ := selfSignedPEM(t)

	if _, err := nodeTLSConfig(store.ScannerNode{Endpoint: "http://scanner:8081", TLSServerCA: ca}); err == nil {
		t.Fatal("http+CA should be rejected")
	}
	if _, err := nodeTLSConfig(store.ScannerNode{Endpoint: "http://scanner:8081", TLSClientCert: cert, TLSClientKey: key}); err == nil {
		t.Fatal("http+cert should be rejected")
	}
	if _, err := nodeTLSConfig(store.ScannerNode{Endpoint: "http://scanner:8081", TLSClientCert: cert}); err == nil {
		t.Fatal("http+cert-only should be rejected as https requirement, not just missing key")
	}
	if cfg, err := nodeTLSConfig(store.ScannerNode{Endpoint: "http://scanner:8081"}); err != nil || cfg != nil {
		t.Fatalf("http without TLS should be nil, got cfg=%v err=%v", cfg, err)
	}
	if cfg, err := nodeTLSConfig(store.ScannerNode{Endpoint: "https://scanner:8081", TLSServerCA: ca}); err != nil || cfg == nil {
		t.Fatalf("https with CA should succeed, got err=%v", err)
	}
	if cfg, err := nodeTLSConfig(store.ScannerNode{Endpoint: "https://scanner:8081", TLSClientCert: cert, TLSClientKey: key}); err != nil || cfg == nil {
		t.Fatalf("https with cert should succeed, got err=%v", err)
	}
}

func TestWithTLSNilIsNoop(t *testing.T) {
	c := NewScannerClient("http://n:8081", "tok")
	if c.WithTLS(nil) != c {
		t.Error("WithTLS(nil) should return the same client unchanged")
	}
}
