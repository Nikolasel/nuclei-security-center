package backend

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// seedBundleScan builds a complete completed scan (target/template-set/policy +
// findings + discovery + coverage) on st and returns its id plus the created
// config records, so tests can either export it or mirror it elsewhere.
func seedBundleScan(t *testing.T, ctx context.Context, st *store.Store) (string, store.Target, store.TemplateSet, store.ScanPolicy) {
	t.Helper()
	suffix := types.NewID()
	target, err := st.CreateTarget(ctx, store.Target{Name: "http-bundle-" + suffix, Hosts: []string{"bundlehttp.invalid"}})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	templateSet, err := st.CreateTemplateSet(ctx, store.TemplateSet{Name: "http-set-" + suffix, Mode: store.TemplateSetModeAll})
	if err != nil {
		t.Fatalf("create template set: %v", err)
	}
	policy, err := st.CreateScanPolicy(ctx, store.ScanPolicy{
		Name:          "http-policy-" + suffix,
		TemplateSetID: templateSet.ID,
	})
	if err != nil {
		t.Fatalf("create scan policy: %v", err)
	}
	scanID, err := st.CreateScan(ctx, types.ScanSpec{
		Targets: target.Hosts,
		Templates: types.TemplateSelector{
			TemplateIDs:     []string{"tpl-http"},
			TemplatesCommit: "http-commit",
		},
	}, store.ScanLink{TargetID: target.ID, TemplateSetID: templateSet.ID, ScanPolicyID: policy.ID, Source: "manual"})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	finding := types.NucleiFinding{
		TemplateID: "tpl-http",
		Host:       "bundlehttp.invalid",
		MatchedAt:  "https://bundlehttp.invalid/",
		Type:       "http",
		Info:       types.NucleiInfo{Name: "http-bundle-check", Severity: "low", Tags: []string{"bundle"}},
	}
	raw, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	if err := st.IngestFinding(ctx, scanID, target.ID, finding, raw); err != nil {
		t.Fatalf("ingest finding: %v", err)
	}
	if err := st.SetScanDiscovered(ctx, scanID, []string{"bundlehttp.invalid:443"}); err != nil {
		t.Fatalf("set discovered: %v", err)
	}
	if err := st.SetScanCoverage(ctx, scanID, []types.EndpointCoverage{{TemplateID: "tpl-http", Endpoint: "bundlehttp.invalid:443"}}, ""); err != nil {
		t.Fatalf("set coverage: %v", err)
	}
	if err := st.MarkComplete(ctx, scanID, "3.3.0", "http-commit"); err != nil {
		t.Fatalf("complete scan: %v", err)
	}
	return scanID, target, templateSet, policy
}

// TestScanBundleHTTPRoundTripPostgres exercises the full HTTP surface: exporting
// a scan as JSON and as zip, importing each back into a second instance through
// the mux, the 409 conflict default, the duplicate policy, and rejection of a
// malformed bundle. It is opt-in like the other PostgreSQL tests.
func TestScanBundleHTTPRoundTripPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	originStore := openScanRequestTestStore(t, ctx, dsn)
	destStore := openScanRequestTestStore(t, ctx, dsn)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	spa := http.NotFoundHandler()
	origin := NewServer(originStore, nil, nil, nil, spa, logger).Handler()
	dest := NewServer(destStore, nil, nil, nil, spa, logger).Handler()

	scanID, _, _, _ := seedBundleScan(t, ctx, originStore)

	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	post := func(h http.Handler, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// JSON export.
	jsonRR := get(origin, "/api/scans/"+scanID+"/export")
	if jsonRR.Code != http.StatusOK {
		t.Fatalf("json export status = %d, body %s", jsonRR.Code, jsonRR.Body.String())
	}
	var jsonBundle types.ScanBundle
	if err := json.Unmarshal(jsonRR.Body.Bytes(), &jsonBundle); err != nil {
		t.Fatalf("decode json export: %v", err)
	}
	if err := jsonBundle.Validate(); err != nil {
		t.Fatalf("exported bundle fails validation: %v", err)
	}
	if jsonBundle.Scan.ID != scanID || len(jsonBundle.Findings) != 1 {
		t.Fatalf("json export contents wrong: %s", jsonRR.Body.String())
	}

	// Zip export must carry the identical manifest.
	zipRR := get(origin, "/api/scans/"+scanID+"/export?format=zip")
	if zipRR.Code != http.StatusOK {
		t.Fatalf("zip export status = %d, want 200", zipRR.Code)
	}
	if ct := zipRR.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("zip export content-type = %q, want application/zip", ct)
	}
	if !strings.HasPrefix(zipRR.Body.String(), "PK\x03\x04") {
		t.Fatalf("zip export is not a zip: %q", zipRR.Body.String()[:min(len(zipRR.Body.String()), 16)])
	}
	zippedManifest, err := readZipBundleManifest(zipRR.Body.Bytes())
	if err != nil {
		t.Fatalf("extract zip manifest: %v", err)
	}
	var zipped types.ScanBundle
	if err := json.Unmarshal(zippedManifest, &zipped); err != nil {
		t.Fatalf("decode zip manifest: %v", err)
	}
	zipped.ExportedAt = time.Time{}
	jsonBundle.ExportedAt = time.Time{}
	jsonBundleBytes, _ := json.Marshal(jsonBundle)
	zippedBytes, _ := json.Marshal(zipped)
	if string(jsonBundleBytes) != string(zippedBytes) {
		t.Fatalf("zip and json exports diverge")
	}
	// The zip must also be re-openable as a real archive containing manifest.json.
	zr, err := zip.NewReader(bytes.NewReader(zipRR.Body.Bytes()), int64(zipRR.Body.Len()))
	if err != nil {
		t.Fatalf("zip export is not a valid archive: %v", err)
	}
	foundManifest := false
	for _, f := range zr.File {
		if f.Name == types.ScanBundleManifestName {
			foundManifest = true
		}
	}
	if !foundManifest {
		t.Fatalf("zip export lacks %s", types.ScanBundleManifestName)
	}

	// Import into the destination. The destination has no origin records, so
	// every reference falls back — the import must still succeed.
	impRR := post(dest, "/api/scans/import", jsonRR.Body.Bytes())
	if impRR.Code != http.StatusCreated {
		t.Fatalf("import status = %d, body %s", impRR.Code, impRR.Body.String())
	}
	var result store.ScanImportResult
	if err := json.Unmarshal(impRR.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode import result: %v", err)
	}
	if result.ScanID != scanID || result.FindingsImported != 1 || result.CoverageMode != store.ImportCoverageIgnore || len(result.Fallbacks) != 3 {
		t.Fatalf("import result wrong: %+v", result)
	}
	importedScan, err := destStore.GetScan(ctx, scanID)
	if err != nil {
		t.Fatalf("get imported scan: %v", err)
	}
	if importedScan.State != string(types.ScanComplete) {
		t.Fatalf("imported scan state = %q, want complete", importedScan.State)
	}

	// Default conflict policy: a second import of the same scan id is a 409.
	againRR := post(dest, "/api/scans/import", jsonRR.Body.Bytes())
	if againRR.Code != http.StatusConflict {
		t.Fatalf("duplicate-id import status = %d, want 409", againRR.Code)
	}

	// Duplicate policy mints a fresh id.
	dupRR := post(dest, "/api/scans/import?conflict=duplicate", jsonRR.Body.Bytes())
	if dupRR.Code != http.StatusCreated {
		t.Fatalf("duplicate import status = %d, body %s", dupRR.Code, dupRR.Body.String())
	}
	var dupResult store.ScanImportResult
	if err := json.Unmarshal(dupRR.Body.Bytes(), &dupResult); err != nil {
		t.Fatalf("decode duplicate result: %v", err)
	}
	if dupResult.ScanID == scanID {
		t.Fatalf("duplicate import reused the original id")
	}

	// Zip import works (same document, wrapped).
	impZip := post(dest, "/api/scans/import?conflict=duplicate", zipRR.Body.Bytes())
	if impZip.Code != http.StatusCreated {
		t.Fatalf("zip import status = %d, body %s", impZip.Code, impZip.Body.String())
	}

	// Rejecting a malformed bundle: wrong format value.
	var malformed types.ScanBundle = jsonBundle
	malformed.Format = "nuclei-security-center/not-a-bundle"
	malformedBytes, _ := json.Marshal(malformed)
	badRR := post(dest, "/api/scans/import", malformedBytes)
	if badRR.Code != http.StatusBadRequest {
		t.Fatalf("malformed bundle status = %d, want 400", badRR.Code)
	}

	// Binary garbage that is not a zip and not JSON.
	garbageRR := post(dest, "/api/scans/import", []byte{0x00, 0xff, 0xfe, 0xfa})
	if garbageRR.Code != http.StatusBadRequest {
		t.Fatalf("garbage bundle status = %d, want 400", garbageRR.Code)
	}
}

// TestScanBundleHTTPImportTrustedCoveragePostgres verifies the explicit operator
// opt-in path: a completed coverage-only bundle may advance mitigation evidence
// when the request says coverage=trust. The default import path remains
// fail-closed and is covered by the store regression test.
func TestScanBundleHTTPImportTrustedCoveragePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewServer(st, nil, nil, nil, http.NotFoundHandler(), logger).Handler()
	invalidModeReq := httptest.NewRequest(http.MethodPost, "/api/scans/import?coverage=unexpected", nil)
	invalidModeRR := httptest.NewRecorder()
	h.ServeHTTP(invalidModeRR, invalidModeReq)
	if invalidModeRR.Code != http.StatusBadRequest {
		t.Fatalf("invalid coverage mode status = %d, want 400", invalidModeRR.Code)
	}

	target, err := st.CreateTarget(ctx, store.Target{
		Name:  "trusted-import-" + types.NewID(),
		Hosts: []string{"trusted-import.invalid"},
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	finding := types.NucleiFinding{
		TemplateID: "tpl-trusted-import",
		Host:       "trusted-import.invalid",
		MatchedAt:  "https://trusted-import.invalid/",
		Type:       "http",
		Info:       types.NucleiInfo{Name: "trusted-import-check", Severity: "high"},
	}
	raw, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	firstScanID, err := st.CreateScan(ctx, types.ScanSpec{Targets: target.Hosts}, store.ScanLink{
		TargetID: target.ID,
		Source:   "manual",
	})
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	if err := st.IngestFinding(ctx, firstScanID, target.ID, finding, raw); err != nil {
		t.Fatalf("ingest finding: %v", err)
	}
	coverage := []types.EndpointCoverage{{TemplateID: finding.TemplateID, Endpoint: "trusted-import.invalid:443"}}
	if err := st.SetScanCoverage(ctx, firstScanID, coverage, ""); err != nil {
		t.Fatalf("set first coverage: %v", err)
	}
	if err := st.MarkComplete(ctx, firstScanID, "3.3.0", "trusted-import"); err != nil {
		t.Fatalf("complete first scan: %v", err)
	}

	bundle := types.ScanBundle{
		Format:        types.ScanBundleFormat,
		FormatVersion: types.ScanBundleFormatVersion,
		ExportedAt:    time.Now().UTC(),
		Config:        types.ScanBundleConfig{TargetID: target.ID},
		Scan: types.ScanBundleScan{
			ID:               types.NewID(),
			State:            string(types.ScanComplete),
			Source:           "manual",
			CreatedAt:        time.Now().UTC().Add(time.Second),
			CoveredEndpoints: coverage,
			Spec:             json.RawMessage(`{"targets":["trusted-import.invalid"]}`),
		},
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("trusted bundle fails validation: %v", err)
	}
	malformedBundle := bundle
	malformedBundle.Scan.ID = types.NewID()
	malformedBundle.Scan.CoveredEndpoints = []types.EndpointCoverage{{Endpoint: "trusted-import.invalid:443"}}
	malformedBody, err := json.Marshal(malformedBundle)
	if err != nil {
		t.Fatalf("marshal malformed trusted bundle: %v", err)
	}
	malformedReq := httptest.NewRequest(http.MethodPost, "/api/scans/import?coverage=trust", bytes.NewReader(malformedBody))
	malformedRR := httptest.NewRecorder()
	h.ServeHTTP(malformedRR, malformedReq)
	if malformedRR.Code != http.StatusBadRequest {
		t.Fatalf("malformed trusted coverage status = %d, want 400", malformedRR.Code)
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal trusted bundle: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/scans/import?coverage=trust", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("trusted import status = %d, body %s", rr.Code, rr.Body.String())
	}
	var result struct {
		CoverageMode string `json:"coverage_mode"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode trusted import result: %v", err)
	}
	if result.CoverageMode != "trust" {
		t.Fatalf("trusted import coverage mode = %q, want trust", result.CoverageMode)
	}

	lifecycle, _, err := st.ListLifecycleFindings(ctx, store.FindingQuery{}, 50, 0)
	if err != nil {
		t.Fatalf("list trusted lifecycle: %v", err)
	}
	if len(lifecycle) != 1 || lifecycle[0].DetectionState != "mitigated" {
		t.Fatalf("trusted import detection state = %+v, want mitigated", lifecycle)
	}
}
