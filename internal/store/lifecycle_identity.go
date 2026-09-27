package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// parseResultIdentity reads the three Nuclei fields that distinguish results
// at one (template, matched_at). Extracted results keep source order for
// display; the discriminator sorts a copy. A non-string extracted-results
// value is treated as absent (same fail-open as the hash).
func parseResultIdentity(raw []byte) (matcherName, extractorName string, extracted []string, err error) {
	var source map[string]json.RawMessage
	if err := json.Unmarshal(raw, &source); err != nil {
		return "", "", nil, err
	}
	matcherName = jsonString(source["matcher-name"])
	extractorName = jsonString(source["extractor-name"])
	extracted = []string{}
	if value := source["extracted-results"]; len(value) > 0 {
		var values []string
		if json.Unmarshal(value, &values) == nil {
			extracted = values
		}
	}
	return matcherName, extractorName, extracted, nil
}

// resultDiscriminator returns a stable discriminator for result dimensions that
// can legitimately produce multiple Nuclei events for one
// (template, matched_at) tuple. Volatile fields such as timestamp, request, and
// response are deliberately excluded so repeated scans retain one lifecycle
// identity.
//
// The canonical byte string is length-prefixed and its extracted results are
// sorted (duplicates retained), making source-array ordering irrelevant without
// introducing delimiter ambiguity. Unit tests pin the format so future runtime
// changes cannot silently fork persisted identities.
func resultDiscriminator(raw []byte) (string, error) {
	matcherName, extractorName, extracted, err := parseResultIdentity(raw)
	if err != nil {
		return "", err
	}
	sorted := append([]string(nil), extracted...)
	sort.Strings(sorted)

	if matcherName == "" && extractorName == "" && len(sorted) == 0 {
		return "", nil
	}

	var canonical strings.Builder
	appendIdentityPart(&canonical, "m", matcherName)
	appendIdentityPart(&canonical, "e", extractorName)
	canonical.WriteByte('x')
	canonical.WriteString(strconv.Itoa(len(sorted)))
	canonical.WriteByte(':')
	for _, value := range sorted {
		appendIdentityPart(&canonical, "", value)
	}

	sum := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(sum[:]), nil
}

func jsonString(raw json.RawMessage) string {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return value
}

func appendIdentityPart(dst *strings.Builder, label, value string) {
	dst.WriteString(label)
	dst.WriteString(strconv.Itoa(len([]byte(value))))
	dst.WriteByte(':')
	dst.WriteString(value)
}
