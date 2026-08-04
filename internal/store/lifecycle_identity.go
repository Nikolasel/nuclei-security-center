package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// resultDiscriminator returns a stable discriminator for result dimensions that
// can legitimately produce multiple Nuclei events for one
// (template, matched_at) tuple. Volatile fields such as timestamp, request, and
// response are deliberately excluded so repeated scans retain one lifecycle
// identity.
//
// The canonical byte string is length-prefixed and its extracted results are
// sorted (duplicates retained), making source-array ordering irrelevant without
// introducing delimiter ambiguity. The database digest function implements the
// same format so SQL and Go never fork future observations.
func resultDiscriminator(raw []byte) (string, error) {
	var source map[string]json.RawMessage
	if err := json.Unmarshal(raw, &source); err != nil {
		return "", err
	}

	matcherName := jsonString(source["matcher-name"])
	extractorName := jsonString(source["extractor-name"])
	var extracted []string
	if value := source["extracted-results"]; len(value) > 0 {
		// Nuclei emits an array of strings. Treat any other historical/source
		// shape as absent rather than letting malformed optional identity
		// metadata reject an otherwise valid finding.
		var values []string
		if json.Unmarshal(value, &values) == nil {
			extracted = values
		}
	}
	sort.Strings(extracted)

	if matcherName == "" && extractorName == "" && len(extracted) == 0 {
		return "", nil
	}

	var canonical strings.Builder
	appendIdentityPart(&canonical, "m", matcherName)
	appendIdentityPart(&canonical, "e", extractorName)
	canonical.WriteByte('x')
	canonical.WriteString(strconv.Itoa(len(extracted)))
	canonical.WriteByte(':')
	for _, value := range extracted {
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
