package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestMarkRunningDoesNotResurrectCancelledScanPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	normalID, err := st.CreateScan(ctx, types.ScanSpec{}, ScanLink{})
	if err != nil {
		t.Fatalf("create normal scan: %v", err)
	}
	marked, err := st.MarkRunning(ctx, normalID, "node-normal")
	if err != nil {
		t.Fatalf("mark normal scan running: %v", err)
	}
	if !marked {
		t.Fatal("MarkRunning(normal) = false, want true")
	}
	normal, err := st.GetScan(ctx, normalID)
	if err != nil {
		t.Fatalf("read normal scan: %v", err)
	}
	if normal.State != string(types.ScanRunning) {
		t.Fatalf("normal scan state = %q, want %q", normal.State, types.ScanRunning)
	}

	cancelledID, err := st.CreateScan(ctx, types.ScanSpec{}, ScanLink{})
	if err != nil {
		t.Fatalf("create cancelled scan: %v", err)
	}
	if _, cancelled, err := st.CancelScan(ctx, cancelledID, "test cancellation"); err != nil {
		t.Fatalf("cancel queued scan: %v", err)
	} else if !cancelled {
		t.Fatal("CancelScan = false, want true")
	}
	marked, err = st.MarkRunning(ctx, cancelledID, "node-should-not-run")
	if err != nil {
		t.Fatalf("mark cancelled scan running: %v", err)
	}
	if marked {
		t.Fatal("MarkRunning(cancelled) = true, want false")
	}
	cancelledRow, err := st.GetScan(ctx, cancelledID)
	if err != nil {
		t.Fatalf("read cancelled scan: %v", err)
	}
	if cancelledRow.State != string(types.ScanCancelled) {
		t.Fatalf("cancelled scan state = %q, want %q", cancelledRow.State, types.ScanCancelled)
	}
	var nodeScanID *string
	if err := st.pool.QueryRow(ctx, `SELECT node_scan_id FROM scans WHERE id = $1`, cancelledID).Scan(&nodeScanID); err != nil {
		t.Fatalf("read cancelled node scan id: %v", err)
	}
	if nodeScanID != nil {
		t.Fatalf("cancelled scan node_scan_id = %q, want NULL", *nodeScanID)
	}
}
