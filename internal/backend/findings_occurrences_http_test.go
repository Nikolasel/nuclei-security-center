package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestHandleListFindingOccurrencesInvalidID(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings/abc/occurrences", nil)
	req.SetPathValue("id", "abc")
	s.handleListFindingOccurrences(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body %q", rr.Code, rr.Body.String())
	}
}

func TestHandleListFindingOccurrencesPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)
	srv := NewServer(st, nil, nil, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")
	h := srv.Handler()

	notFound := httptest.NewRecorder()
	h.ServeHTTP(notFound, httptest.NewRequest(http.MethodGet, "/api/findings/999999/occurrences", nil))
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("unknown finding status = %d, want 404 body %q", notFound.Code, notFound.Body.String())
	}

	target, err := st.CreateTarget(ctx, store.Target{Name: "occ-http-target-" + types.NewID(), Hosts: []string{"occ-http.invalid"}})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	spec := types.ScanSpec{
		Targets:   target.Hosts,
		Templates: types.TemplateSelector{TemplateIDs: []string{"http-missing-header"}, TemplatesCommit: "test"},
	}
	scanID, err := st.CreateScan(ctx, spec, store.ScanLink{TargetID: target.ID})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	finding := types.NucleiFinding{
		TemplateID: "http-missing-header",
		Host:       "occ-http.invalid",
		MatchedAt:  "https://occ-http.invalid",
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
	detail, err := st.GetLifecycleFinding(ctx, mustFindingID(t, ctx, st, scanID))
	if err != nil {
		t.Fatalf("GetLifecycleFinding: %v", err)
	}

	ok := httptest.NewRecorder()
	h.ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "/api/findings/"+strconv.FormatInt(detail.ID, 10)+"/occurrences?limit=50", nil))
	if ok.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 body %q", ok.Code, ok.Body.String())
	}
	var page occurrencesPage
	if err := json.NewDecoder(ok.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ScanID != scanID {
		t.Fatalf("page = %+v, want one occurrence of scan %s", page, scanID)
	}
	if page.Limit != 50 || page.Offset != 0 {
		t.Fatalf("pagination envelope = limit %d offset %d", page.Limit, page.Offset)
	}
}

func mustFindingID(t *testing.T, ctx context.Context, st *store.Store, scanID string) int64 {
	t.Helper()
	rows, _, err := st.ListFindings(ctx, store.FindingFilter{ScanID: scanID, Limit: 10})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(rows) == 0 || rows[0].FindingID == nil {
		t.Fatalf("no finding_id on occurrence rows %+v", rows)
	}
	return *rows[0].FindingID
}
