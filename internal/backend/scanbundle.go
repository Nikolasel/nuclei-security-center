package backend

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Scan bundle (#136): export a complete scan result as a self-contained,
// versioned manifest (JSON, or the same document zipped as manifest.json) and
// import it on another instance. Like a scan-results file (a Nessus .ness
// import), the bundle carries the scan record, the resolved config that
// produced it, and every occurrence with its preserved Nuclei raw JSON — never
// the exporter's globally deduplicated finding lifecycle. Import re-derives the
// destination's own lifecycle (dedup identity, detection state, first/last-seen,
// mitigation counters, analyst overlays) from the results exactly as if it had
// scanned the target itself.
//
// Import is fail-soft on references: a scan policy / template set / target /
// node / schedule that doesn't exist locally falls back to its default (NULL),
// exactly like a deleted entity leaves behind. It is fail-hard on the bundle
// itself: the manifest must parse, validate, and be a version we understand.

// handleExportScanBundle streams one scan as a downloadable bundle
// (GET /api/scans/{id}/export?format=json|zip). Reads are viewer-level like the
// other exports; the bundle is assembled server-side.
func (s *Server) handleExportScanBundle(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "zip" {
		http.Error(w, "unsupported format (want json or zip)", http.StatusBadRequest)
		return
	}

	id := r.PathValue("id")
	bundle, err := s.store.ScanBundleForExport(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		s.serverError(w, "export scan bundle", err)
		return
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	if format == "zip" {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%s-%s.nsc-bundle.zip"`, id, stamp))
		zw := zip.NewWriter(w)
		fw, err := zw.Create(types.ScanBundleManifestName)
		if err != nil {
			s.serverError(w, "write scan bundle", err)
			return
		}
		if err := json.NewEncoder(fw).Encode(bundle); err != nil {
			s.log.Warn("encode scan bundle zip", "scan_id", id, "err", err)
		}
		if err := zw.Close(); err != nil {
			s.log.Warn("close scan bundle zip", "scan_id", id, "err", err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%s-%s.nsc-bundle.json"`, id, stamp))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bundle); err != nil {
		s.log.Warn("encode scan bundle", "scan_id", id, "err", err)
	}
}

// isZipBundle sniffs the PK zip magic: the local-file header (PK\x03\x04), the
// empty-archive end-of-central-directory (PK\x05\x06), and the spanned marker
// (PK\x07\x08).
func isZipBundle(body []byte) bool {
	if len(body) < 4 {
		return false
	}
	if body[0] != 'P' || body[1] != 'K' {
		return false
	}
	switch {
	case body[2] == 3 && body[3] == 4:
		return true
	case body[2] == 5 && body[3] == 6:
		return true
	case body[2] == 7 && body[3] == 8:
		return true
	default:
		return false
	}
}

// readZipBundleManifest extracts manifest.json from a zip bundle. It rejects a
// zip with more than one manifest.json (so no ambiguity about which reader
// would pick) and bounds the decompressed size by ScanBundleMaxManifest, well
// below the request-body ceiling, so a zip bomb cannot expand to the full
// upload cap.
func readZipBundleManifest(body []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("invalid zip bundle: %w", err)
	}
	var manifest []byte
	matches := 0
	for _, f := range zr.File {
		if f.Name != types.ScanBundleManifestName {
			continue
		}
		matches++
		if matches > 1 {
			return nil, fmt.Errorf("bundle contains more than one %s", types.ScanBundleManifestName)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", types.ScanBundleManifestName, err)
		}
		manifest, err = io.ReadAll(io.LimitReader(rc, types.ScanBundleMaxManifest+1))
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", types.ScanBundleManifestName, err)
		}
		if len(manifest) > types.ScanBundleMaxManifest {
			return nil, fmt.Errorf("bundle %s exceeds the %d MiB limit", types.ScanBundleManifestName, types.ScanBundleMaxManifest>>20)
		}
	}
	if manifest == nil {
		return nil, fmt.Errorf("bundle contains no %s", types.ScanBundleManifestName)
	}
	return manifest, nil
}

// handleImportScanBundle recreates a scan from a bundle on this instance
// (POST /api/scans/import?conflict=error|duplicate). Operator-level and
// audited; the response reports what was imported and which references fell
// back to their defaults.
func (s *Server) handleImportScanBundle(w http.ResponseWriter, r *http.Request) {
	conflict := store.ImportConflictError
	switch strings.TrimSpace(r.URL.Query().Get("conflict")) {
	case "", "error":
		conflict = store.ImportConflictError
	case "duplicate":
		conflict = store.ImportConflictDuplicate
	default:
		http.Error(w, "invalid conflict policy (want error or duplicate)", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, types.ScanBundleMaxUpload)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read bundle: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty bundle", http.StatusBadRequest)
		return
	}

	manifest := body
	if isZipBundle(body) {
		manifest, err = readZipBundleManifest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	var b types.ScanBundle
	if err := json.Unmarshal(manifest, &b); err != nil {
		http.Error(w, "invalid scan bundle: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := b.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := s.store.ImportScanBundle(r.Context(), &b, conflict)
	if err != nil {
		if errors.Is(err, store.ErrScanBundleConflict) {
			http.Error(w, "a scan with id "+b.Scan.ID+" already exists (delete it, or re-import with conflict=duplicate)", http.StatusConflict)
			return
		}
		s.serverError(w, "import scan bundle", err)
		return
	}
	addAuditFields(r,
		slog.String("scan_id", result.ScanID),
		slog.Int("findings_imported", result.FindingsImported),
		slog.Int("lifecycle_created", result.LifecycleCreated),
		slog.Int("lifecycle_updated", result.LifecycleUpdated),
		slog.Int("reference_fallbacks", len(result.Fallbacks)),
	)
	writeJSON(w, http.StatusCreated, result)
}
