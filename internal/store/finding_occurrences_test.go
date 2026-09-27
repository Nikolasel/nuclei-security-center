package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestListFindingOccurrencesPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	target, err := st.CreateTarget(ctx, Target{Name: "occ-list-target-" + types.NewID(), Hosts: []string{"occ.invalid"}})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	ingest := func(occurredAt time.Time) string {
		t.Helper()
		spec := types.ScanSpec{
			Targets:   target.Hosts,
			Templates: types.TemplateSelector{TemplateIDs: []string{"http-missing-header"}, TemplatesCommit: "test"},
		}
		scanID, err := st.CreateScan(ctx, spec, ScanLink{TargetID: target.ID})
		if err != nil {
			t.Fatalf("create scan: %v", err)
		}
		finding := types.NucleiFinding{
			TemplateID: "http-missing-header",
			Host:       "occ.invalid",
			MatchedAt:  "https://occ.invalid",
			Type:       "http",
			Info:       types.NucleiInfo{Name: "Missing header", Severity: "medium"},
		}
		raw, err := json.Marshal(finding)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := st.IngestFinding(ctx, scanID, target.ID, finding, raw); err != nil {
			t.Fatalf("ingest: %v", err)
		}
		if _, err := st.pool.Exec(ctx, `UPDATE findings SET created_at = $2 WHERE scan_id = $1`, scanID, occurredAt); err != nil {
			t.Fatalf("stamp created_at: %v", err)
		}
		return scanID
	}

	older := ingest(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	newer := ingest(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	var findingID int64
	if err := st.pool.QueryRow(ctx, `SELECT finding_id FROM findings WHERE scan_id = $1`, newer).Scan(&findingID); err != nil {
		t.Fatalf("lookup finding id: %v", err)
	}

	_, _, err = st.ListFindingOccurrences(ctx, findingID+1_000_000, 50, 0)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown finding err = %v, want ErrNotFound", err)
	}

	rows, total, err := st.ListFindingOccurrences(ctx, findingID, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].ScanID != newer || rows[1].ScanID != older {
		t.Fatalf("order = %s then %s, want newer %s then older %s", rows[0].ScanID, rows[1].ScanID, newer, older)
	}
	if rows[0].Host != "occ.invalid" || rows[0].MatchedAt != "https://occ.invalid" {
		t.Fatalf("row fields = %+v", rows[0])
	}

	page, pageTotal, err := st.ListFindingOccurrences(ctx, findingID, 1, 0)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if pageTotal != 2 || len(page) != 1 || page[0].ScanID != newer {
		t.Fatalf("first page = %+v total %d, want newer only", page, pageTotal)
	}
	page, pageTotal, err = st.ListFindingOccurrences(ctx, findingID, 1, 1)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if pageTotal != 2 || len(page) != 1 || page[0].ScanID != older {
		t.Fatalf("second page = %+v total %d, want older only", page, pageTotal)
	}

	if _, err := st.pool.Exec(ctx, `DELETE FROM findings WHERE finding_id = $1`, findingID); err != nil {
		t.Fatalf("delete occurrences: %v", err)
	}
	empty, emptyTotal, err := st.ListFindingOccurrences(ctx, findingID, 50, 0)
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if emptyTotal != 0 || empty == nil || len(empty) != 0 {
		t.Fatalf("empty = %+v total %d, want empty slice", empty, emptyTotal)
	}
}
