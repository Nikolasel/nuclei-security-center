// Package templates parses Nuclei YAML just far enough to validate and index
// the catalog. It deliberately retains the original YAML rather than trying to
// serialize this representation back to YAML.
package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Metadata is the extracted, filterable portion of one Nuclei YAML document.
type Metadata struct {
	ID            string
	Path          string
	YAML          string
	ContentSHA256 string
	Name          string
	Author        string
	Severity      string
	Description   string
	Tags          []string
}

// ErrNotTemplate marks YAML files (repository metadata, CI config, etc.) that
// are valid YAML but do not contain a top-level Nuclei template id.
var ErrNotTemplate = errors.New("not a nuclei template")

// Parse reads one Nuclei template document. The caller supplies its repository-
// relative path, which is normalized to slash separators for portable bundles.
func Parse(path string, body []byte) (Metadata, error) {
	path = filepath.ToSlash(filepath.Clean(path))
	if path == "." || strings.HasPrefix(path, "../") || strings.HasPrefix(path, "/") {
		return Metadata{}, fmt.Errorf("unsafe template path %q", path)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return Metadata{}, fmt.Errorf("parse YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Metadata{}, errors.New("multiple YAML documents are not supported")
		}
		return Metadata{}, fmt.Errorf("parse YAML: %w", err)
	}
	root, err := mappingRoot(&doc)
	if err != nil {
		return Metadata{}, err
	}
	id := scalar(mappingValue(root, "id"))
	if id == "" {
		return Metadata{}, ErrNotTemplate
	}
	info, err := mappingRoot(mappingValue(root, "info"))
	if err != nil {
		return Metadata{}, fmt.Errorf("template %q info: %w", id, err)
	}
	name := scalar(mappingValue(info, "name"))
	if name == "" {
		return Metadata{}, fmt.Errorf("template %q: info.name is required", id)
	}
	tags, err := stringValues(mappingValue(info, "tags"))
	if err != nil {
		return Metadata{}, fmt.Errorf("template %q tags: %w", id, err)
	}
	authors, err := stringValues(mappingValue(info, "author"))
	if err != nil {
		return Metadata{}, fmt.Errorf("template %q author: %w", id, err)
	}
	hash := sha256.Sum256(body)
	severity := strings.ToLower(strings.TrimSpace(scalar(mappingValue(info, "severity"))))
	if severity == "" {
		severity = "unknown"
	}
	return Metadata{
		ID: id, Path: path, YAML: string(body), ContentSHA256: hex.EncodeToString(hash[:]),
		Name: name, Author: strings.Join(authors, ", "), Severity: severity,
		Description: scalar(mappingValue(info, "description")), Tags: tags,
	}, nil
}

func mappingRoot(n *yaml.Node) (*yaml.Node, error) {
	if n == nil {
		return nil, errors.New("missing mapping")
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) != 1 {
			return nil, errors.New("expected one YAML document")
		}
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil, errors.New("expected a mapping")
	}
	return n, nil
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(n.Value)
}

func stringValues(n *yaml.Node) ([]string, error) {
	if n == nil {
		return nil, nil
	}
	var values []string
	switch n.Kind {
	case yaml.ScalarNode:
		values = strings.Split(n.Value, ",")
	case yaml.SequenceNode:
		for _, child := range n.Content {
			if child.Kind != yaml.ScalarNode {
				return nil, errors.New("must contain only scalar values")
			}
			values = append(values, child.Value)
		}
	default:
		return nil, errors.New("must be a scalar or list")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}
