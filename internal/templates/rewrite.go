package templates

import (
	"bytes"
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// RewriteID changes only the top-level template id and re-encodes the YAML.
// Import's on_conflict=rename is the one case where byte-for-byte preservation
// is impossible by definition: the Nuclei document's own identity must change
// with the catalog key. yaml.v3 keeps the document structure and comments while
// avoiding a fragile textual replacement.
func RewriteID(body []byte, newID string) ([]byte, error) {
	if newID == "" {
		return nil, errors.New("new template id is required")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	root, err := mappingRoot(&doc)
	if err != nil {
		return nil, err
	}
	id := mappingValue(root, "id")
	if id == nil || id.Kind != yaml.ScalarNode {
		return nil, ErrNotTemplate
	}
	id.Value = newID
	id.Tag = "!!str"

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("encode YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close YAML encoder: %w", err)
	}
	return out.Bytes(), nil
}
