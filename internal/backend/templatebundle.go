package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// errDuplicateBundlePath marks a catalog that cannot be packed: two templates
// would occupy the same tar member name. The catalog's UNIQUE (source, path)
// constraint scopes uniqueness per source only, so an upstream repo-relative
// path can collide with a synthesized custom path (upstream custom/x.yaml vs
// custom template id x) while both rows are individually valid. The node
// extracts each member with O_TRUNC and verifies against the manifest, so such
// a bundle is rejected wholesale as ErrInvalidBundle — freezing distribution to
// every node. Failing here keeps that outcome loud, early, and actionable.
var errDuplicateBundlePath = errors.New("duplicate template bundle path")

// buildCatalogBundle packs every active template into the gzipped tar the node's
// POST /v1/templates/bundle expects: each template's verbatim YAML at its path,
// plus a manifest.json (id/path/sha256 per template + the canonical digest). The
// returned digest is types.BundleDigest over the manifest entries — the value the
// node will report back as templates_commit. Byte-for-byte YAML keeps the digest
// a faithful record of exactly what the node runs.
//
// Packing invariant, asserted here rather than trusted to the schema: every tar
// member must resolve to a unique name under the SAME rules the node applies
// when extracting — the cleaned form of the slash path (extractTarGz's
// duplicate key). Backslashes therefore stay literal: scanner nodes extract on
// Linux, where a backslash is an ordinary filename character, so `http\a.yaml`
// and `http/a.yaml` are distinct files there and must not be flagged here.
// (The DB constrains (source, path) within one source; cross-source collisions
// are still representable and fail here instead of shipping a bundle every
// node rejects.)
func buildCatalogBundle(bodies []store.Template) (data []byte, digest string, err error) {
	entries := make([]types.TemplateBundleEntry, len(bodies))
	byPath := make(map[string]string, len(bodies)) // resolved member name -> first claimant id
	for i, t := range bodies {
		entries[i] = types.TemplateBundleEntry{ID: t.ID, Path: t.Path, SHA256: t.ContentSHA256}
		member := path.Clean(t.Path)
		if first, dup := byPath[member]; dup {
			return nil, "", fmt.Errorf(
				"%w: %q would be written by both template %q and %q; rename or delete one",
				errDuplicateBundlePath, t.Path, first, t.ID,
			)
		}
		byPath[member] = t.ID
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
