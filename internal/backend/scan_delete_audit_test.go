package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestScanDeleteRouteAuditCategoryPostgres verifies that the destructive scan
// route is distinguishable from routine dispatch traffic in the stable audit
// vocabulary. It is opt-in with the other PostgreSQL HTTP integration tests.
func TestScanDeleteRouteAuditCategoryPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	scanID, err := st.CreateScan(ctx, types.ScanSpec{}, store.ScanLink{})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if _, cancelled, err := st.CancelScan(ctx, scanID, "test cancellation"); err != nil {
		t.Fatalf("cancel scan: %v", err)
	} else if !cancelled {
		t.Fatal("cancel scan = false, want true")
	}

	var logs bytes.Buffer
	srv := NewServer(st, nil, nil, nil, http.NotFoundHandler(), slog.New(slog.NewJSONHandler(&logs, nil)), os.TempDir())
	req := httptest.NewRequest(http.MethodDelete, "/api/scans/"+scanID, nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete scan status = %d, want 204; body = %s", rr.Code, rr.Body.String())
	}

	event := lastAudit(t, &logs)
	if event["event_id"] != eventConfigChanged {
		t.Fatalf("scan.delete event_id = %v, want %q", event["event_id"], eventConfigChanged)
	}
	if event["action"] != "scan.delete" {
		t.Fatalf("audit action = %v, want scan.delete", event["action"])
	}
}

// TestScanDeleteSystemAuditCategory pins the same category for retention's
// background deletion path, which has no HTTP route to exercise.
func TestScanDeleteSystemAuditCategory(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))

	logSystemAudit(context.Background(), log, eventConfigChanged, "scan.delete", "scan", "scan1")
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	if event["event_id"] != eventConfigChanged {
		t.Fatalf("system scan.delete event_id = %v, want %q", event["event_id"], eventConfigChanged)
	}
}
