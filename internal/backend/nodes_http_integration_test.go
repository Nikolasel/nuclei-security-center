package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestUpdateNodeHandlerHTTPAndStoreIntegration(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)
	s := &Server{store: st, orch: &Orchestrator{}, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}

	cert, key := selfSignedPEM(t)
	ca, _ := selfSignedPEM(t)
	// Use Server handler directly to exercise validation and store.
	created, err := st.CreateScannerNode(ctx, store.ScannerNode{
		Name: "node-mtls", Endpoint: "https://scanner-mtls:8081", Token: "tok-" + ca[:8],
		TLSServerCA: ca, TLSClientCert: cert, TLSClientKey: key,
		CIDRs: []string{"10.10.0.0/16"}, MaxConcurrentScans: 20,
	})
	if err != nil {
		t.Fatalf("create scanner node: %v", err)
	}
	// Verify created node has TLS.
	got, err := st.GetScannerNode(ctx, created.ID)
	if err != nil {
		t.Fatalf("get created node: %v", err)
	}
	if got.TLSServerCA == "" || got.TLSClientCert == "" || got.TLSClientKey == "" {
		t.Fatalf("created node should have TLS, got CA len %d cert len %d key len %d", len(got.TLSServerCA), len(got.TLSClientCert), len(got.TLSClientKey))
	}

	// 1. Transition https+mTLS -> http plain should succeed and clear the paired key.
	// UI sends blank CA/cert + omitted key (NodesPage.tsx:71-74).
	updatePayload := map[string]any{
		"name": "node-mtls", "endpoint": " http://scanner-mtls:8081 ",
		"cidrs": []string{" 10.10.0.0/16 "},
		"tags":  []string{}, "max_concurrent_scans": 20,
		"tls_server_ca": "", "tls_client_cert": "",
		// tls_client_key omitted -> keep-on-blank in old code, but new code clears when cert empty
	}
	body, _ := json.Marshal(updatePayload)
	req := httptest.NewRequest(http.MethodPut, "/api/nodes/"+created.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", created.ID)
	req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	rr := httptest.NewRecorder()
	s.handleUpdateNode(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT http plain transition status = %d, want 200 body %q", rr.Code, rr.Body.String())
	}
	// Read back from store: TLS should be fully cleared, endpoint trimmed, CIDRs trimmed.
	after, err := st.GetScannerNode(ctx, created.ID)
	if err != nil {
		t.Fatalf("get after http transition: %v", err)
	}
	if after.TLSServerCA != "" || after.TLSClientCert != "" || after.TLSClientKey != "" {
		t.Fatalf("after http plain transition, TLS should be cleared, got CA=%q cert=%q key=%q", after.TLSServerCA, after.TLSClientCert, after.TLSClientKey)
	}
	if after.Endpoint != "http://scanner-mtls:8081" {
		t.Fatalf("endpoint should be trimmed, got %q", after.Endpoint)
	}
	if len(after.CIDRs) != 1 || after.CIDRs[0] != "10.10.0.0/16" {
		t.Fatalf("CIDRs should be trimmed, got %v", after.CIDRs)
	}
	if after.Name != "node-mtls" {
		t.Fatalf("name should be trimmed, got %q", after.Name)
	}

	// 2. Re-enable mTLS on https should succeed.
	updatePayload2 := map[string]any{
		"name": "node-mtls", "endpoint": "https://scanner-mtls:8081",
		"cidrs": []string{"10.10.0.0/16"}, "max_concurrent_scans": 20,
		"tls_server_ca": ca, "tls_client_cert": cert, "tls_client_key": key,
	}
	body, _ = json.Marshal(updatePayload2)
	req = httptest.NewRequest(http.MethodPut, "/api/nodes/"+created.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", created.ID)
	req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	rr = httptest.NewRecorder()
	s.handleUpdateNode(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT re-enable mTLS on https status = %d, want 200 body %q", rr.Code, rr.Body.String())
	}
	after, err = st.GetScannerNode(ctx, created.ID)
	if err != nil {
		t.Fatalf("get after re-enable: %v", err)
	}
	if after.TLSServerCA == "" || after.TLSClientCert == "" || after.TLSClientKey == "" {
		t.Fatalf("after re-enable mTLS, TLS should be present, got CA %q cert %q key %q", after.TLSServerCA, after.TLSClientCert, after.TLSClientKey)
	}

	// 3. Attempt http+TLS should be rejected 400 and leave the stored row unchanged (still https+mTLS).
	badPayload := map[string]any{
		"name": "node-mtls", "endpoint": "http://scanner-mtls:8081",
		"cidrs": []string{"10.10.0.0/16"}, "max_concurrent_scans": 20,
		"tls_server_ca": ca,
	}
	body, _ = json.Marshal(badPayload)
	req = httptest.NewRequest(http.MethodPut, "/api/nodes/"+created.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", created.ID)
	req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	rr = httptest.NewRecorder()
	s.handleUpdateNode(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT http+TLS status = %d, want 400 body %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "https") {
		t.Fatalf("PUT http+TLS body %q should mention https", rr.Body.String())
	}
	// Verify DB unchanged: still https+mTLS.
	afterBad, err := st.GetScannerNode(ctx, created.ID)
	if err != nil {
		t.Fatalf("get after bad http+TLS: %v", err)
	}
	if afterBad.Endpoint != "https://scanner-mtls:8081" {
		t.Fatalf("endpoint should remain https after rejected http+TLS, got %q", afterBad.Endpoint)
	}
	if afterBad.TLSServerCA == "" {
		t.Fatalf("TLS should remain after rejected http+TLS, got empty CA")
	}
}
