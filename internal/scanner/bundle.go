package scanner

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// manifestName is the well-known manifest path at the bundle root.
const manifestName = "manifest.json"

// maxBundleBytes caps the total decompressed size of a bundle, so a malicious or
// corrupt gzip stream can't exhaust the node's disk (a decompression bomb —
// CWE-409). The full community catalog is well under this; custom sets far less.
const maxBundleBytes = 512 << 20 // 512 MiB

// ErrInvalidBundle marks a bundle the node refuses: bad archive, path escape,
// hash mismatch, or a digest that doesn't match the manifest. It maps to a 4xx —
// the bundle is the caller's fault, not a node fault.
var ErrInvalidBundle = errors.New("invalid template bundle")

// ErrBundleBusy means a verified bundle could not be activated because one or
// more scans hold the active tree's shared read lock. The HTTP layer maps it to
// 409 so the backend can retry rather than treating it as a bad bundle.
var ErrBundleBusy = errors.New("template bundle busy")

// ErrMissingTemplates marks a scan contract that names ids absent from the
// active manifest. The node rejects it before launching Nuclei, fail closed.
var ErrMissingTemplates = errors.New("active template bundle is missing requested templates")

// bundleStore owns the node's active template tree. The backend pushes an
// immutable, verified bundle (backend→node only, invariant #2); the node extracts
// it to a staging dir, verifies every file against the manifest, then atomically
// swaps it into place. The node never pulls or reaches back to the backend.
type bundleStore struct {
	root string // holds active/, the digest marker, and transient staging dirs

	mu     sync.RWMutex
	digest string // digest of the currently active bundle ("" = none yet)
}

// newBundleStore prepares the store under dir and recovers the active digest from
// a previous run (the tree persists on the node's volume even though scans don't).
func newBundleStore(dir string) (*bundleStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create bundle dir: %w", err)
	}
	b := &bundleStore{root: dir}
	if data, err := os.ReadFile(b.digestPath()); err == nil {
		b.digest = strings.TrimSpace(string(data))
	}
	return b, nil
}

func (b *bundleStore) activePath() string { return filepath.Join(b.root, "active") }
func (b *bundleStore) digestPath() string { return filepath.Join(b.root, "active.digest") }

// activeDigest returns the digest of the currently active bundle, or "".
func (b *bundleStore) activeDigest() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.digest
}

// apply extracts, verifies, and atomically activates a bundle read from r (a
// gzipped tar). On any verification failure it leaves the current active bundle
// untouched and returns ErrInvalidBundle. It is safe to call concurrently; a
// mutex serializes the activate swap.
func (b *bundleStore) apply(r io.Reader) (types.TemplateBundleStatus, error) {
	staging, err := os.MkdirTemp(b.root, "staging-")
	if err != nil {
		return types.TemplateBundleStatus{}, fmt.Errorf("create staging dir: %w", err)
	}
	// Best-effort cleanup: on success the dir has been renamed away already, so
	// RemoveAll is a no-op; on failure it removes the partial extraction.
	defer func() { _ = os.RemoveAll(staging) }()

	if err := extractTarGz(r, staging); err != nil {
		return types.TemplateBundleStatus{}, err
	}
	manifest, err := readManifest(staging)
	if err != nil {
		return types.TemplateBundleStatus{}, err
	}
	if err := verifyManifest(staging, manifest); err != nil {
		return types.TemplateBundleStatus{}, err
	}

	// Fail fast instead of waiting behind a long scan. A waiting writer would
	// make sync.RWMutex block new readers and starve newly queued scans; TryLock
	// preserves the chosen "running scans win, bundle push retries" policy.
	if !b.mu.TryLock() {
		return types.TemplateBundleStatus{}, fmt.Errorf("%w: scans are running", ErrBundleBusy)
	}
	defer b.mu.Unlock()
	if err := b.activate(staging, manifest.Digest); err != nil {
		return types.TemplateBundleStatus{}, err
	}
	return types.TemplateBundleStatus{TemplatesCommit: manifest.Digest, TemplateCount: len(manifest.Templates)}, nil
}

// activate swaps the verified staging dir in as the active tree and records the
// digest. The caller holds mu exclusively, so no scan can observe the
// remove/rename window. The digest marker is written last so a crash mid-swap is
// detectable.
func (b *bundleStore) activate(staging, digest string) error {
	active := b.activePath()
	if err := os.RemoveAll(active); err != nil {
		return fmt.Errorf("remove old bundle: %w", err)
	}
	if err := os.Rename(staging, active); err != nil {
		return fmt.Errorf("activate bundle: %w", err)
	}
	if err := os.WriteFile(b.digestPath(), []byte(digest), 0o640); err != nil {
		return fmt.Errorf("record bundle digest: %w", err)
	}
	b.digest = digest
	return nil
}

// lockTemplates takes the active tree's shared lock, validates the requested
// bundle digest, resolves every template id through manifest.json, and returns
// absolute paths plus an unlock function. The caller must hold the lock for the
// scan's entire lifetime so activation can never swap files under Nuclei.
//
// RLock intentionally blocks if an activation already holds the exclusive lock:
// a scan starting mid-activation queues briefly, then sees the fully swapped
// tree. Conversely, activation uses TryLock and is refused while any scan runs.
type lockedTemplate struct {
	ID   string
	Path string
}

func (b *bundleStore) lockTemplates(templateIDs []string, templatesCommit string) ([]lockedTemplate, func(), error) {
	b.mu.RLock()
	unlock := b.mu.RUnlock

	if len(templateIDs) == 0 {
		unlock()
		return nil, nil, fmt.Errorf("%w: scan spec has no template_ids", ErrMissingTemplates)
	}
	if templatesCommit == "" {
		unlock()
		return nil, nil, errors.New("scan spec has no templates_commit")
	}
	manifest, err := readManifest(b.activePath())
	if err != nil {
		unlock()
		return nil, nil, fmt.Errorf(
			"%w: %s (active manifest unavailable: %v)",
			ErrMissingTemplates, strings.Join(uniqueSorted(templateIDs), ", "), err,
		)
	}

	byID := make(map[string]string, len(manifest.Templates))
	for _, entry := range manifest.Templates {
		byID[entry.ID] = entry.Path
	}
	seen := make(map[string]struct{}, len(templateIDs))
	templates := make([]lockedTemplate, 0, len(templateIDs))
	var missing []string
	for _, id := range templateIDs {
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		rel, ok := byID[id]
		if !ok {
			missing = append(missing, id)
			continue
		}
		path, err := safeJoin(b.activePath(), rel)
		if err != nil {
			unlock()
			return nil, nil, fmt.Errorf("resolve active template %q: %w", id, err)
		}
		templates = append(templates, lockedTemplate{ID: id, Path: path})
	}
	if len(missing) > 0 {
		unlock()
		sort.Strings(missing)
		return nil, nil, fmt.Errorf("%w: %s", ErrMissingTemplates, strings.Join(missing, ", "))
	}
	if manifest.Digest != b.digest || templatesCommit != manifest.Digest {
		unlock()
		return nil, nil, fmt.Errorf(
			"template bundle commit mismatch: scan requested %q, active bundle is %q",
			templatesCommit, manifest.Digest,
		)
	}
	return templates, unlock, nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// extractTarGz unpacks a gzipped tar into dest, refusing anything that isn't a
// plain file or directory and any path that escapes dest (zip-slip, CWE-22). The
// total decompressed size is bounded (CWE-409).
func extractTarGz(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: gzip: %v", ErrInvalidBundle, err)
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxBundleBytes+1))
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: tar: %v", ErrInvalidBundle, err)
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return fmt.Errorf("create bundle dir: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return fmt.Errorf("create bundle parent: %w", err)
			}
			n, err := writeRegular(target, tr, maxBundleBytes-total)
			if err != nil {
				return err
			}
			total += n
		default:
			// Symlinks/hardlinks/devices are a path-escape and privilege vector;
			// a template bundle is plain YAML files, so anything else is rejected.
			return fmt.Errorf("%w: unsupported tar entry %q (type %d)", ErrInvalidBundle, hdr.Name, hdr.Typeflag)
		}
	}
	return nil
}

// writeRegular copies at most limit+... bytes of a tar entry to disk, failing if
// the running total would exceed the bundle cap.
func writeRegular(target string, tr io.Reader, remaining int64) (int64, error) {
	if remaining <= 0 {
		return 0, fmt.Errorf("%w: bundle exceeds %d bytes", ErrInvalidBundle, int64(maxBundleBytes))
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return 0, fmt.Errorf("create bundle file: %w", err)
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(tr, remaining+1))
	if err != nil {
		return 0, fmt.Errorf("write bundle file: %w", err)
	}
	if n > remaining {
		return 0, fmt.Errorf("%w: bundle exceeds %d bytes", ErrInvalidBundle, int64(maxBundleBytes))
	}
	return n, nil
}

// safeJoin resolves a bundle-relative name against dest, rejecting (not silently
// neutralizing) anything unsafe: absolute paths and ".." traversal (zip-slip,
// CWE-22). A malformed path means a malformed bundle, so it fails closed.
func safeJoin(dest, name string) (string, error) {
	slash := filepath.ToSlash(name)
	clean := filepath.Clean(slash)
	if filepath.IsAbs(name) || strings.HasPrefix(slash, "/") || clean == "." ||
		clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: unsafe path %q", ErrInvalidBundle, name)
	}
	target := filepath.Join(dest, filepath.FromSlash(clean))
	// Defense in depth: confirm the join really stayed within dest.
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: unsafe path %q", ErrInvalidBundle, name)
	}
	return target, nil
}

// readManifest loads and parses manifest.json from the extracted tree.
func readManifest(dir string) (types.TemplateBundleManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return types.TemplateBundleManifest{}, fmt.Errorf("%w: missing %s: %v", ErrInvalidBundle, manifestName, err)
	}
	var m types.TemplateBundleManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return types.TemplateBundleManifest{}, fmt.Errorf("%w: bad %s: %v", ErrInvalidBundle, manifestName, err)
	}
	return m, nil
}

// verifyManifest checks every listed template exists at its path with the right
// sha256, and that the manifest's own Digest matches the canonical BundleDigest.
// A file on disk not covered by the manifest, or a hash mismatch, fails closed.
func verifyManifest(dir string, m types.TemplateBundleManifest) error {
	if len(m.Templates) == 0 {
		return fmt.Errorf("%w: manifest lists no templates", ErrInvalidBundle)
	}
	if want := types.BundleDigest(m.Templates); want != m.Digest {
		return fmt.Errorf("%w: manifest digest %q != computed %q", ErrInvalidBundle, m.Digest, want)
	}
	for _, e := range m.Templates {
		target, err := safeJoin(dir, e.Path)
		if err != nil {
			return err
		}
		sum, err := fileSHA256(target)
		if err != nil {
			return fmt.Errorf("%w: template %q: %v", ErrInvalidBundle, e.ID, err)
		}
		if sum != e.SHA256 {
			return fmt.Errorf("%w: template %q hash %s != manifest %s", ErrInvalidBundle, e.ID, sum, e.SHA256)
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
