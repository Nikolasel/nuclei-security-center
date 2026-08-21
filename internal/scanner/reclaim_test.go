package scanner

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestDeleteScanRemovesDirAndMapEntry(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRunner("/bin/true", "/bin/true", "connect", dir, 10)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	defer r.Close()
	id := "scan-123"
	workDir := filepath.Join(dir, id)
	if err := os.MkdirAll(workDir, 0750); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(workDir, "results.jsonl"), []byte("{}\n"), 0640)
	r.mu.Lock()
	r.scans[id] = &job{
		status: types.ScanStatus{ID: id, State: types.ScanComplete},
		dir:    workDir,
	}
	r.scans[id].finishedAt = time.Now()
	r.mu.Unlock()

	if r.ScanCount() != 1 {
		t.Fatalf("count %d want 1", r.ScanCount())
	}
	if err := r.DeleteScan(id); err != nil {
		t.Fatalf("DeleteScan: %v", err)
	}
	if _, err := os.Stat(workDir); !os.IsNotExist(err) {
		t.Fatalf("workDir still exists after DeleteScan")
	}
	if r.ScanCount() != 0 {
		t.Fatalf("count after delete %d want 0", r.ScanCount())
	}
	if err := r.DeleteScan("nope"); err != ErrScanNotFound {
		t.Fatalf("Delete missing = %v, want ErrScanNotFound", err)
	}
}

func TestDeleteScanOnRunningReturnsConflict(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewRunner("/bin/true", "/bin/true", "connect", dir, 10)
	defer r.Close()
	r.mu.Lock()
	r.scans["running"] = &job{status: types.ScanStatus{ID: "running", State: types.ScanRunning}, dir: filepath.Join(dir, "running")}
	r.mu.Unlock()
	if err := r.DeleteScan("running"); err != ErrScanNotTerminal {
		t.Fatalf("Delete running = %v, want ErrScanNotTerminal", err)
	}
	// HTTP layer must map that to 409
	srv := NewServer(r, "secret-token-12345678901234567890", slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	req := httptest.NewRequest(http.MethodDelete, "/v1/scans/running", nil)
	req.Header.Set("Authorization", "Bearer secret-token-12345678901234567890")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("HTTP Delete running = %d want 409 body=%q", w.Code, w.Body.String())
	}
}

func TestCleanupExpiredRespectsRetention(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewRunner("/bin/true", "/bin/true", "connect", dir, 10)
	defer r.Close()
	expired := filepath.Join(dir, "expired")
	fresh := filepath.Join(dir, "fresh")
	running := filepath.Join(dir, "running2")
	for _, d := range []string{expired, fresh, running} {
		_ = os.MkdirAll(d, 0750)
	}
	now := time.Now()
	r.mu.Lock()
	r.scans["expired"] = &job{status: types.ScanStatus{ID: "expired", State: types.ScanComplete}, dir: expired, finishedAt: now.Add(-2 * scanRetention)}
	r.scans["fresh"] = &job{status: types.ScanStatus{ID: "fresh", State: types.ScanFailed}, dir: fresh, finishedAt: now}
	r.scans["running2"] = &job{status: types.ScanStatus{ID: "running2", State: types.ScanRunning}, dir: running}
	r.mu.Unlock()

	r.cleanupExpired()

	if _, err := os.Stat(expired); !os.IsNotExist(err) {
		t.Fatalf("expired dir not removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh dir should remain: %v", err)
	}
	if _, err := os.Stat(running); err != nil {
		t.Fatalf("running dir should remain: %v", err)
	}
	if _, ok := r.scans["expired"]; ok {
		t.Fatalf("expired still in map")
	}
	if _, ok := r.scans["fresh"]; !ok {
		t.Fatalf("fresh missing")
	}
	if _, ok := r.scans["running2"]; !ok {
		t.Fatalf("running missing")
	}
	// Retention is 1h and bounds the window between node terminal and backend
	// fetch; it only needs to exceed a few seconds normally, but the
	// cross-package invariant (ScanRetention > ingestTail+nodeOverhead=13m) is
	// asserted in internal/backend/scan_retention_test.go.
	if ScanRetention != time.Hour {
		t.Fatalf("ScanRetention %s want 1h", ScanRetention)
	}
}

func TestOrphanSweepPreservesBundleAndRemovesUntracked(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewRunner("/bin/true", "/bin/true", "connect", dir, 10)
	defer r.Close()
	// Orphan created after NewRunner (so startup sweep already ran). Age it
	// past scanRetention so the periodic sweep considers it eligible; a fresh
	// dir must not be removed (live validation race, see runner.go:333).
	oldTime := time.Now().Add(-2 * scanRetention)
	orphan := filepath.Join(dir, "orphan-uuid")
	validationTmp := filepath.Join(dir, "template-validation-abc")
	_ = os.MkdirAll(orphan, 0750)
	_ = os.MkdirAll(validationTmp, 0750)
	_ = os.Chtimes(orphan, oldTime, oldTime)
	_ = os.Chtimes(validationTmp, oldTime, oldTime)
	// Keep a tracked scan dir (fresh, must remain even though age check would
	// otherwise qualify it)
	tracked := filepath.Join(dir, "tracked")
	_ = os.MkdirAll(tracked, 0750)
	r.mu.Lock()
	r.scans["tracked"] = &job{status: types.ScanStatus{ID: "tracked", State: types.ScanRunning}, dir: tracked}
	r.mu.Unlock()
	// Fresh orphan (not old enough) must be left alone
	freshOrphan := filepath.Join(dir, "fresh-orphan")
	_ = os.MkdirAll(freshOrphan, 0750)
	// Also create a stray file (should be left alone)
	_ = os.WriteFile(filepath.Join(dir, "some-file.txt"), []byte("x"), 0640)

	bundleDir := filepath.Join(dir, "_bundle")
	if _, err := os.Stat(bundleDir); err != nil {
		t.Fatalf("bundle missing: %v", err)
	}
	if err := r.cleanupOrphanedDirs(true); err != nil {
		t.Fatalf("cleanupOrphanedDirs: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan not removed")
	}
	if _, err := os.Stat(validationTmp); !os.IsNotExist(err) {
		t.Fatalf("validation tmp not removed")
	}
	if _, err := os.Stat(freshOrphan); err != nil {
		t.Fatalf("fresh orphan should remain (age-gated): %v", err)
	}
	if _, err := os.Stat(tracked); err != nil {
		t.Fatalf("tracked should remain: %v", err)
	}
	if _, err := os.Stat(bundleDir); err != nil {
		t.Fatalf("bundle should remain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "some-file.txt")); err != nil {
		t.Fatalf("stray file should be preserved: %v", err)
	}
}

func TestStartupOrphanCleanup(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "stale-scan")
	_ = os.MkdirAll(stale, 0750)
	r, _ := NewRunner("/bin/true", "/bin/true", "connect", dir, 10)
	defer r.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale dir not cleaned on startup")
	}
}

func TestHTTPDeleteScanHandlerStatusCodes(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewRunner("/bin/true", "/bin/true", "connect", dir, 10)
	defer r.Close()
	srv := NewServer(r, "secret-token-12345678901234567890", slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	id := "to-delete"
	workDir := filepath.Join(dir, id)
	_ = os.MkdirAll(workDir, 0750)
	r.mu.Lock()
	r.scans[id] = &job{status: types.ScanStatus{ID: id, State: types.ScanComplete}, dir: workDir, finishedAt: time.Now()}
	r.mu.Unlock()

	// missing auth => 401
	req := httptest.NewRequest(http.MethodDelete, "/v1/scans/"+id, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth = %d want 401", w.Code)
	}
	// not found => 404
	req = httptest.NewRequest(http.MethodDelete, "/v1/scans/missing", nil)
	req.Header.Set("Authorization", "Bearer secret-token-12345678901234567890")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing = %d want 404", w.Code)
	}
	// completed => 204 and dir removed
	req = httptest.NewRequest(http.MethodDelete, "/v1/scans/"+id, nil)
	req.Header.Set("Authorization", "Bearer secret-token-12345678901234567890")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d want 204 body=%q", w.Code, w.Body.String())
	}
	if _, err := os.Stat(workDir); !os.IsNotExist(err) {
		t.Fatalf("dir not removed")
	}
	// second delete => 404
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("second delete = %d want 404", w.Code)
	}
}

func TestRunnerCloseStopsReaper(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewRunner("/bin/true", "/bin/true", "connect", dir, 10)
	// Close should not panic and should be idempotent
	r.Close()
	r.Close()
	select {
	case <-r.done:
	default:
		t.Fatalf("done not closed")
	}
}
