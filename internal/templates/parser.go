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

// Parse reads one Nuclei template document for the upstream catalog. It is
// deliberately lenient: the community tree is authoritative (Nuclei already runs
// it), so we must not silently drop a template over our own stricter opinions —
// only genuinely unusable YAML (no id, malformed info) is rejected.
func Parse(path string, body []byte) (Metadata, error) {
	return parse(path, body, false)
}

// ParseCustom parses a user-authored template with the extra sanity checks we
// hold uploads to but not the upstream tree: a known severity and at least one
// executable section (protocol block or workflow). This catches an obviously
// inert or typo'd template at write time instead of letting it sit in the
// catalog and silently never match. It is NOT a substitute for Nuclei's own
// validation — a scanner-side `nuclei -validate` check is the authoritative
// gate planned for a later slice; this is the cheap first line of defense.
func ParseCustom(path string, body []byte) (Metadata, error) {
	return parse(path, body, true)
}

func parse(path string, body []byte, strict bool) (Metadata, error) {
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
	if strings.ContainsRune(id, '\x00') {
		return Metadata{}, fmt.Errorf("template id contains a NUL byte")
	}
	info, err := mappingRoot(mappingValue(root, "info"))
	if err != nil {
		return Metadata{}, fmt.Errorf("template %q info: %w", id, err)
	}
	name := indexText(scalar(mappingValue(info, "name")))
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
	severity := strings.ToLower(indexText(scalar(mappingValue(info, "severity"))))
	if severity == "" {
		severity = "unknown"
	}
	if strict {
		if !knownSeverity(severity) {
			return Metadata{}, fmt.Errorf("template %q: unknown severity %q (want one of %s)", id, severity, strings.Join(nucleiSeverities, "/"))
		}
		if !hasExecutableSection(root) {
			return Metadata{}, fmt.Errorf("template %q: no executable section (expected one of %s, or workflows)", id, strings.Join(protocolSections, "/"))
		}
	}
	return Metadata{
		ID: id, Path: path, YAML: string(body), ContentSHA256: hex.EncodeToString(hash[:]),
		Name: name, Author: strings.Join(authors, ", "), Severity: severity,
		Description: indexText(scalar(mappingValue(info, "description"))), Tags: tags,
	}, nil
}

// nucleiSeverities is Nuclei's fixed severity vocabulary (info.severity). A
// custom template outside this set is a typo we reject rather than store.
var nucleiSeverities = []string{"info", "low", "medium", "high", "critical", "unknown"}

func knownSeverity(s string) bool {
	for _, v := range nucleiSeverities {
		if s == v {
			return true
		}
	}
	return false
}

// protocolSections are Nuclei's executable top-level keys. A template with none
// of these (and no workflows/flow) can never match anything, so for a custom
// upload we treat its absence as an authoring mistake. "requests"/"tcp" are the
// legacy aliases for http/network; kept so a hand-written template using them
// isn't wrongly rejected.
var protocolSections = []string{"http", "requests", "dns", "network", "tcp", "ssl", "websocket", "whois", "file", "headless", "code", "javascript", "flow"}

func hasExecutableSection(root *yaml.Node) bool {
	for _, k := range protocolSections {
		if mappingValue(root, k) != nil {
			return true
		}
	}
	// Workflow files carry a top-level `workflows:` list instead of a protocol
	// block; they're valid, executable Nuclei documents too.
	return mappingValue(root, "workflows") != nil
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

// indexText makes decoded YAML scalar values safe for Postgres TEXT columns.
// YAML double-quoted strings may legally contain escapes such as \0, which
// yaml.v3 decodes to U+0000; Postgres rejects that code point. The authoritative
// YAML is retained byte-for-byte separately, so the searchable/display
// projection preserves the meaning as the printable two-character escape.
func indexText(s string) string {
	return strings.ReplaceAll(s, "\x00", `\0`)
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
		v = indexText(strings.TrimSpace(v))
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
