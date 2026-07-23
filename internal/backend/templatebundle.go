package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// buildCatalogBundle packs every active template into the gzipped tar the node's
// POST /v1/templates/bundle expects: each template's verbatim YAML at its path,
// plus a manifest.json (id/path/sha256 per template + the canonical digest). The
// returned digest is types.BundleDigest over the manifest entries — the value the
// node will report back as templates_commit. Byte-for-byte YAML keeps the digest
// a faithful record of exactly what the node runs.
func buildCatalogBundle(bodies []store.Template) (data []byte, digest string, err error) {
	entries := make([]types.TemplateBundleEntry, len(bodies))
	for i, t := range bodies {
		entries[i] = types.TemplateBundleEntry{ID: t.ID, Path: t.Path, SHA256: t.ContentSHA256}
	}
	digest = types.BundleDigest(entries)
	manifest, err := json.Marshal(types.TemplateBundleManifest{Digest: digest, Templates: entries})
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := writeBundleFile(tw, "manifest.json", manifest); err != nil {
		return nil, "", err
	}
	for _, t := range bodies {
		if err := writeBundleFile(tw, t.Path, []byte(t.YAML)); err != nil {
			return nil, "", fmt.Errorf("bundle template %q: %w", t.ID, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	if err := gz.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), digest, nil
}

func writeBundleFile(tw *tar.Writer, name string, content []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}
