package backend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
)

// memStore is an in-memory ObjectStore for tests. It mirrors the contract the
// handlers rely on — notably Get returning ErrObjectNotFound for a missing key.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemStore() *memStore { return &memStore{objects: map[string][]byte{}} }

func (m *memStore) Put(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = b
	return nil
}

func (m *memStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func TestRawObjectKey(t *testing.T) {
	if got := rawObjectKey("abc-123"); got != "scans/abc-123/raw.jsonl" {
		t.Errorf("rawObjectKey = %q", got)
	}
}

func TestMemStoreContract(t *testing.T) {
	ctx := context.Background()
	s := newMemStore()

	if _, err := s.Get(ctx, "missing"); !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("Get(missing) err = %v, want ErrObjectNotFound", err)
	}

	want := []byte(`{"template-id":"x"}` + "\n")
	if err := s.Put(ctx, "k", bytes.NewReader(want), int64(len(want)), "application/x-ndjson"); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip = %q, want %q", got, want)
	}
}

// With no object store configured, the raw-download route 404s before touching
// the database.
func TestHandleGetScanRawDisabled(t *testing.T) {
	s := &Server{} // archive == nil
	rr := httptest.NewRecorder()
	s.handleGetScanRaw(rr, httptest.NewRequest("GET", "/api/scans/abc/raw", nil))

	if rr.Code != 404 {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("not configured")) {
		t.Errorf("body = %q, want it to mention storage not configured", rr.Body.String())
	}
}
