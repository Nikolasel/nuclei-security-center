package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSignedCert generates a throwaway cert+key and writes them as PEM,
// returning the two file paths.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
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
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, _ := os.Create(certPath)
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.Create(keyPath)
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()
	return certPath, keyPath
}

func TestServerTLSFromEnvDisabled(t *testing.T) {
	// No env set → plain HTTP.
	cfg, err := ServerTLSFromEnv()
	if err != nil || cfg != nil {
		t.Fatalf("ServerTLSFromEnv() = (%v, %v), want (nil, nil)", cfg, err)
	}
}

func TestServerTLSFromEnvTLSOnly(t *testing.T) {
	cert, key := writeSelfSignedCert(t)
	t.Setenv("SCANNER_TLS_CERT", cert)
	t.Setenv("SCANNER_TLS_KEY", key)

	cfg, err := ServerTLSFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatal("expected a server certificate")
	}
	if RequiresClientCert(cfg) {
		t.Error("no client CA set, mTLS should be off")
	}
}

func TestServerTLSFromEnvMutual(t *testing.T) {
	cert, key := writeSelfSignedCert(t)
	ca, _ := writeSelfSignedCert(t) // reuse a cert as a CA bundle
	t.Setenv("SCANNER_TLS_CERT", cert)
	t.Setenv("SCANNER_TLS_KEY", key)
	t.Setenv("SCANNER_CLIENT_CA", ca)

	cfg, err := ServerTLSFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	// The acceptance criterion: a client without a valid cert is rejected.
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs not set")
	}
	if !RequiresClientCert(cfg) {
		t.Error("RequiresClientCert should be true under mTLS")
	}
}

func TestServerTLSFromEnvKeyWithoutCert(t *testing.T) {
	_, key := writeSelfSignedCert(t)
	t.Setenv("SCANNER_TLS_KEY", key) // cert missing
	if _, err := ServerTLSFromEnv(); err == nil {
		t.Fatal("key without cert should error")
	}
}
