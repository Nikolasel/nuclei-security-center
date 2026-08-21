package backend

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
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

const (
	maxConcurrentScanBundleImports = 1
	scanBundleImportRetryAfter     = "10"

	scanBundleZipEndSignature        uint32 = 0x06054b50
	scanBundleZip64EndSignature      uint32 = 0x06064b50
	scanBundleZip64LocatorSignature  uint32 = 0x07064b50
	scanBundleZipDigitalSignature    uint32 = 0x05054b50
	scanBundleZipEndLen                     = 22
	scanBundleZip64EndLen                   = 56
	scanBundleZip64LocatorLen               = 20
	scanBundleZipDirectoryHeaderLen         = 46
	scanBundleZipMaxCentralDirectory        = 8 << 20
	scanBundleZipTailLen                    = 65 * 1024
)

var errScanBundleUploadTooLarge = errors.New("scan bundle upload exceeds its maximum size")

func scanBundleLimitError(maxBytes int64) error {
	if maxBytes == types.ScanBundleMaxUpload {
		return fmt.Errorf("%w: %d MiB maximum", errScanBundleUploadTooLarge, maxBytes>>20)
	}
	return fmt.Errorf("scan bundle exceeds the %d MiB limit", maxBytes>>20)
}

func isHTTPMaxBytesError(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

func (s *Server) tryAcquireScanBundleImport() (func(), bool) {
	s.scanBundleImportOnce.Do(func() {
		if s.scanBundleImportSlots == nil {
			s.scanBundleImportSlots = make(chan struct{}, maxConcurrentScanBundleImports)
		}
	})
	select {
	case s.scanBundleImportSlots <- struct{}{}:
		return func() { <-s.scanBundleImportSlots }, true
	default:
		return nil, false
	}
}

// scanZipBundleDirectory validates and counts the central directory without
// constructing archive/zip's []*zip.File slice. It returns only an error;
// callers discard the directory details.

// readAtFull reads exactly p from r. ReaderAt implementations are allowed to
// return a short read with io.EOF, so checking only the error is insufficient.
func readAtFull(r io.ReaderAt, p []byte, off int64) error {
	if off < 0 {
		return errors.New("negative archive offset")
	}
	n, err := r.ReadAt(p, off)
	if n != len(p) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func findScanBundleZipEnd(buf []byte) int {
	for i := len(buf) - scanBundleZipEndLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:i+4]) != scanBundleZipEndSignature {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(buf[i+20 : i+22]))
		if i+scanBundleZipEndLen+commentLen <= len(buf) {
			return i
		}
	}
	return -1
}

func readScanBundleZip64End(r io.ReaderAt, size, legacyEnd int64) (uint64, uint64, uint64, int64, error) {
	locatorOffset := legacyEnd - scanBundleZip64LocatorLen
	var locator [scanBundleZip64LocatorLen]byte
	if err := readAtFull(r, locator[:], locatorOffset); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read zip64 locator: %w", err)
	}
	if binary.LittleEndian.Uint32(locator[0:4]) != scanBundleZip64LocatorSignature {
		return 0, 0, 0, 0, errors.New("zip64 locator is missing")
	}
	if binary.LittleEndian.Uint32(locator[4:8]) != 0 || binary.LittleEndian.Uint32(locator[16:20]) != 1 {
		return 0, 0, 0, 0, errors.New("multi-disk zip64 bundles are not supported")
	}
	zip64End := binary.LittleEndian.Uint64(locator[8:16])
	if zip64End > uint64(^uint64(0)>>1) || zip64End > uint64(size) {
		return 0, 0, 0, 0, errors.New("zip64 end record is outside the bundle")
	}
	if uint64(size)-zip64End < scanBundleZip64EndLen {
		return 0, 0, 0, 0, errors.New("zip64 end record is truncated")
	}
	var end [scanBundleZip64EndLen]byte
	if err := readAtFull(r, end[:], int64(zip64End)); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read zip64 end record: %w", err)
	}
	if binary.LittleEndian.Uint32(end[0:4]) != scanBundleZip64EndSignature {
		return 0, 0, 0, 0, errors.New("zip64 end record is invalid")
	}
	recordSize := binary.LittleEndian.Uint64(end[4:12])
	if recordSize < 44 || recordSize > uint64(size)-zip64End-12 {
		return 0, 0, 0, 0, errors.New("zip64 end record has an invalid size")
	}
	return binary.LittleEndian.Uint64(end[32:40]),
		binary.LittleEndian.Uint64(end[40:48]),
		binary.LittleEndian.Uint64(end[48:56]), int64(zip64End), nil
}

// scanZipBundleDirectory validates and counts the central directory before
// zip.NewReader can materialize one *zip.File per entry. The declared count is
// not trusted on its own: a malformed archive can claim a small count while
// carrying a much larger directory, so the fixed-size directory headers are
// walked as well.
func scanZipBundleDirectory(r io.ReaderAt, size int64) error {
	if size < scanBundleZipEndLen {
		return errors.New("zip bundle is too small")
	}
	tailLen := int64(scanBundleZipTailLen)
	if tailLen > size {
		tailLen = size
	}
	tail := make([]byte, int(tailLen))
	n, err := r.ReadAt(tail, size-tailLen)
	if n != len(tail) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("read zip end record: %w", err)
	}
	endInTail := findScanBundleZipEnd(tail)
	if endInTail < 0 {
		return errors.New("zip end record is missing")
	}
	legacyEnd := size - tailLen + int64(endInTail)
	legacyEntries := uint64(binary.LittleEndian.Uint16(tail[endInTail+10 : endInTail+12]))
	legacySize := uint64(binary.LittleEndian.Uint32(tail[endInTail+12 : endInTail+16]))
	legacyOffset := uint64(binary.LittleEndian.Uint32(tail[endInTail+16 : endInTail+20]))
	directoryEnd := legacyEnd
	entries := legacyEntries
	directorySize := legacySize
	directoryOffset := legacyOffset
	if legacyEntries == 0xffff || legacySize == 0xffffffff || legacyOffset == 0xffffffff {
		entries, directorySize, directoryOffset, directoryEnd, err = readScanBundleZip64End(r, size, legacyEnd)
		if err != nil {
			return fmt.Errorf("invalid zip64 bundle: %w", err)
		}
	}
	maxEntries := uint64(types.ScanBundleMaxEntries)
	if entries > maxEntries {
		return fmt.Errorf("bundle exceeds %d zip entries", types.ScanBundleMaxEntries)
	}
	if directorySize > scanBundleZipMaxCentralDirectory {
		return fmt.Errorf("bundle central directory exceeds the %d MiB limit", scanBundleZipMaxCentralDirectory>>20)
	}
	if directoryEnd < 0 || directorySize > uint64(directoryEnd) || directoryEnd > size {
		return errors.New("zip central directory is outside the bundle")
	}
	if directoryOffset > uint64(^uint64(0)>>1) || directoryOffset > uint64(size) {
		return errors.New("zip central directory offset is invalid")
	}
	directoryStart := directoryEnd - int64(directorySize)
	baseOffset := directoryStart - int64(directoryOffset)
	if baseOffset < 0 {
		return errors.New("zip central directory offset is invalid")
	}
	if baseOffset > 0 {
		// archive/zip has a compatibility fallback that ignores a positive
		// prepended-data offset when the raw directory offset also begins with a
		// central-directory header. Reject that ambiguous layout here so the
		// pre-scan and zip.NewReader cannot examine different byte ranges.
		var rawHeader [4]byte
		if err := readAtFull(r, rawHeader[:], int64(directoryOffset)); err == nil &&
			binary.LittleEndian.Uint32(rawHeader[:]) == 0x02014b50 {
			return errors.New("zip central directory offset is ambiguous")
		}
	}
	var header [scanBundleZipDirectoryHeaderLen]byte
	var signatureBytes [4]byte
	actualEntries := uint64(0)
	for offset := directoryStart; offset < directoryEnd; {
		remaining := directoryEnd - offset
		if remaining < int64(len(signatureBytes)) {
			return errors.New("zip central directory is truncated")
		}
		if err := readAtFull(r, signatureBytes[:], offset); err != nil {
			return fmt.Errorf("read zip central directory: %w", err)
		}
		signature := binary.LittleEndian.Uint32(signatureBytes[:])
		if signature == scanBundleZipDigitalSignature {
			if remaining < 6 {
				return errors.New("zip central directory digital signature is truncated")
			}
			var digitalSize [2]byte
			if err := readAtFull(r, digitalSize[:], offset+4); err != nil {
				return fmt.Errorf("read zip digital signature: %w", err)
			}
			if uint64(6)+uint64(binary.LittleEndian.Uint16(digitalSize[:])) != uint64(remaining) {
				return errors.New("zip central directory has trailing data")
			}
			break
		}
		if remaining < scanBundleZipDirectoryHeaderLen {
			return errors.New("zip central directory is truncated")
		}
		copy(header[0:4], signatureBytes[:])
		if err := readAtFull(r, header[4:], offset+4); err != nil {
			return fmt.Errorf("read zip central directory: %w", err)
		}
		if signature != 0x02014b50 {
			return errors.New("zip central directory entry is invalid")
		}
		nameLen := uint64(binary.LittleEndian.Uint16(header[28:30]))
		extraLen := uint64(binary.LittleEndian.Uint16(header[30:32]))
		commentLen := uint64(binary.LittleEndian.Uint16(header[32:34]))
		entrySize := uint64(scanBundleZipDirectoryHeaderLen) + nameLen + extraLen + commentLen
		if entrySize > uint64(remaining) {
			return errors.New("zip central directory entry is truncated")
		}
		actualEntries++
		if actualEntries > maxEntries {
			return fmt.Errorf("bundle exceeds %d zip entries", types.ScanBundleMaxEntries)
		}
		offset += int64(entrySize)
	}
	if actualEntries != entries {
		return fmt.Errorf("zip central directory contains %d entries, header declares %d", actualEntries, entries)
	}
	return nil
}

func openScanBundleManifest(r io.ReaderAt, size int64) (io.ReadCloser, error) {
	if err := scanZipBundleDirectory(r, size); err != nil {
		return nil, fmt.Errorf("invalid zip bundle: %w", err)
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("invalid zip bundle: %w", err)
	}
	var manifest *zip.File
	for _, f := range zr.File {
		if f.Name != types.ScanBundleManifestName {
			continue
		}
		if manifest != nil {
			return nil, fmt.Errorf("bundle contains more than one %s", types.ScanBundleManifestName)
		}
		manifest = f
	}
	if manifest == nil {
		return nil, fmt.Errorf("bundle contains no %s", types.ScanBundleManifestName)
	}
	rc, err := manifest.Open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", types.ScanBundleManifestName, err)
	}
	return rc, nil
}

type scanBundleCountingReader struct {
	r io.Reader
	n int64
}

func (r *scanBundleCountingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

func decodeScanBundleJSON(r io.Reader, maxBytes int64) (*types.ScanBundle, error) {
	return decodeScanBundleJSONWithLimit(r, maxBytes, types.ScanBundleMaxFindings)
}

func decodeScanBundleJSONWithLimit(r io.Reader, maxBytes int64, maxFindings int) (*types.ScanBundle, error) {
	counted := &scanBundleCountingReader{r: io.LimitReader(r, maxBytes+1)}
	dec := json.NewDecoder(counted)

	// Decode the bundle with findings as raw JSON so we can stream the
	// findings array with a count bound. Decoding the full []ScanBundleFinding
	// at once would amplify wire bytes ~70x (3 bytes "[{},"/wire vs ~200 bytes
	// decoded), letting a 512 MiB / 128 MiB byte-capped body OOM via tens of
	// millions of minimal objects. The envelope is first buffered as RawMessage
	// (≤ maxBytes) and then the findings array is streamed element-by-element;
	// peak heap is O(maxBytes) for the raw buffer plus O(ScanBundleMaxFindings)
	// structs, so the 70x amplification is gone while wire bytes remain bounded
	// by the byte ceilings.
	var raw struct {
		Format        string                 `json:"format"`
		FormatVersion int                    `json:"format_version"`
		ExportedAt    time.Time              `json:"exported_at"`
		Scan          types.ScanBundleScan   `json:"scan"`
		Config        types.ScanBundleConfig `json:"config"`
		Findings      json.RawMessage        `json:"findings"`
	}
	if err := dec.Decode(&raw); err != nil {
		if counted.n > maxBytes || (maxBytes == types.ScanBundleMaxUpload && isHTTPMaxBytesError(err)) {
			return nil, scanBundleLimitError(maxBytes)
		}
		return nil, fmt.Errorf("invalid scan bundle: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		// isHTTPMaxBytesError only arises on the raw upload path where r wraps
		// http.MaxBytesReader (maxBytes == ScanBundleMaxUpload); the manifest
		// path reads from a spool *os.File, so only counted.n matters there.
		if counted.n > maxBytes || (maxBytes == types.ScanBundleMaxUpload && isHTTPMaxBytesError(err)) {
			return nil, scanBundleLimitError(maxBytes)
		}
		return nil, fmt.Errorf("invalid scan bundle: %w", err)
	}
	if counted.n > maxBytes {
		return nil, scanBundleLimitError(maxBytes)
	}

	trimmed := bytes.TrimSpace(raw.Findings)
	var findings []types.ScanBundleFinding
	if len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null")) {
		if trimmed[0] != '[' {
			return nil, fmt.Errorf("invalid scan bundle: findings must be an array")
		}
		dec2 := json.NewDecoder(bytes.NewReader(trimmed))
		tok, err := dec2.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid scan bundle: %w", err)
		}
		if delim, ok := tok.(json.Delim); !ok || delim != '[' {
			return nil, fmt.Errorf("invalid scan bundle: findings must be an array")
		}
		findings = make([]types.ScanBundleFinding, 0, 1024)
		for dec2.More() {
			if len(findings) >= maxFindings {
				return nil, fmt.Errorf("scan bundle: %d findings exceeds the %d limit", len(findings)+1, maxFindings)
			}
			var f types.ScanBundleFinding
			if err := dec2.Decode(&f); err != nil {
				return nil, fmt.Errorf("invalid scan bundle: %w", err)
			}
			findings = append(findings, f)
		}
		if _, err := dec2.Token(); err != nil {
			return nil, fmt.Errorf("invalid scan bundle: %w", err)
		}
		if err := ensureJSONEOF(dec2); err != nil {
			return nil, fmt.Errorf("invalid scan bundle: %w", err)
		}
	}

	b := &types.ScanBundle{
		Format:        raw.Format,
		FormatVersion: raw.FormatVersion,
		ExportedAt:    raw.ExportedAt,
		Scan:          raw.Scan,
		Config:        raw.Config,
		Findings:      findings,
	}
	return b, nil
}

func (s *Server) decodeScanBundleUpload(w http.ResponseWriter, r *http.Request) (*types.ScanBundle, error) {
	r.Body = http.MaxBytesReader(w, r.Body, types.ScanBundleMaxUpload)
	var prefix [4]byte
	n, err := io.ReadFull(r.Body, prefix[:])
	if n == 0 {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errors.New("empty bundle")
		}
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	input := io.MultiReader(bytes.NewReader(prefix[:n]), r.Body)
	if !isZipBundle(prefix[:n]) {
		return decodeScanBundleJSON(input, types.ScanBundleMaxUpload)
	}

	spoolDir := s.exportSpoolDir
	if spoolDir == "" {
		spoolDir = os.TempDir()
	}
	tmp, err := os.CreateTemp(spoolDir, "nsc-scan-bundle-*")
	if err != nil {
		return nil, fmt.Errorf("prepare scan bundle: %w", err)
	}
	tmpName := tmp.Name()
	cleanupName := tmpName
	if err := os.Remove(tmpName); err == nil {
		cleanupName = ""
	}
	// Keep the open spool unlinked where the platform permits it. This mirrors
	// the findings-export spool and prevents a killed process from leaving a
	// full upload behind; the named-file fallback is cleaned up below.
	defer func() {
		_ = tmp.Close()
		if cleanupName != "" {
			_ = os.Remove(cleanupName)
		}
	}()
	spooled, err := io.Copy(tmp, input)
	if err != nil {
		if isHTTPMaxBytesError(err) {
			return nil, scanBundleLimitError(types.ScanBundleMaxUpload)
		}
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	if spooled == 0 {
		return nil, errors.New("empty bundle")
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind bundle: %w", err)
	}
	rc, err := openScanBundleManifest(tmp, spooled)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return decodeScanBundleJSON(rc, types.ScanBundleMaxManifest)
}

// handleImportScanBundle recreates a scan from a bundle on this instance
// (POST /api/scans/import?conflict=error|duplicate&coverage=ignore|trust).
// Operator-level and audited; coverage=ignore is the safe default and coverage=trust
// is an explicit opt-in to use imported endpoint coverage for mitigation.
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
	coverageMode := store.ImportCoverageIgnore
	switch strings.TrimSpace(r.URL.Query().Get("coverage")) {
	case "", string(store.ImportCoverageIgnore):
		coverageMode = store.ImportCoverageIgnore
	case string(store.ImportCoverageTrust):
		coverageMode = store.ImportCoverageTrust
	default:
		http.Error(w, "invalid coverage mode (want ignore or trust)", http.StatusBadRequest)
		return
	}

	releaseImport, ok := s.tryAcquireScanBundleImport()
	if !ok {
		w.Header().Set("Retry-After", scanBundleImportRetryAfter)
		http.Error(w, "another scan bundle import is already in progress", http.StatusTooManyRequests)
		return
	}
	defer releaseImport()

	b, err := s.decodeScanBundleUpload(w, r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errScanBundleUploadTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, err.Error(), status)
		return
	}
	if err := b.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := s.store.ImportScanBundle(r.Context(), b, conflict, coverageMode)
	if err != nil {
		if errors.Is(err, store.ErrInvalidImportedCoverage) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
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
		slog.String("coverage_mode", string(result.CoverageMode)),
		slog.Int("reference_fallbacks", len(result.Fallbacks)),
	)
	writeJSON(w, http.StatusCreated, result)
}
