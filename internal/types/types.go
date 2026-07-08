// Package types holds the wire contracts shared between the backend and the
// scanner node, plus the subset of Nuclei's JSONL output we parse for indexing.
package types

import "github.com/google/uuid"

// ScanState is the lifecycle of a scan, tracked by both the scanner node
// (in memory, for one run) and the backend (durably, in Postgres).
type ScanState string

const (
	ScanQueued   ScanState = "queued"   // backend-only: created, not yet dispatched
	ScanRunning  ScanState = "running"  // dispatched to a node and executing
	ScanComplete ScanState = "complete" // finished, results ingested
	ScanFailed   ScanState = "failed"   // dispatch/run/ingest error
)

// ScanSpec is the request body for POST /v1/scans on the scanner node. It is
// self-contained: the node needs nothing else to run a scan.
type ScanSpec struct {
	Targets   []string         `json:"targets"`
	Templates TemplateSelector `json:"templates"`
	Options   ScanOptions      `json:"options"`
}

// TemplateSelector picks which templates run. GitRef pins the template repo
// commit for reproducibility; the filters map to Nuclei's -severity/-tags flags.
type TemplateSelector struct {
	GitRef     string   `json:"git_ref,omitempty"`
	Severities []string `json:"severities,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Paths      []string `json:"paths,omitempty"`
}

// ScanOptions maps to Nuclei's rate/concurrency/timeout knobs.
type ScanOptions struct {
	RateLimit   int `json:"rate_limit,omitempty"`
	Concurrency int `json:"concurrency,omitempty"`
	TimeoutSec  int `json:"timeout_sec,omitempty"`
}

// ScanStatus is the response from GET /v1/scans/{id} on the scanner node.
type ScanStatus struct {
	ID              string    `json:"id"`
	State           ScanState `json:"state"`
	NucleiVersion   string    `json:"nuclei_version,omitempty"`
	TemplatesCommit string    `json:"templates_commit,omitempty"`
	FindingCount    int       `json:"finding_count"`
	Error           string    `json:"error,omitempty"`
}

// StartScanResponse is the 202 body from POST /v1/scans.
type StartScanResponse struct {
	ScanID string `json:"scan_id"`
}

// NucleiFinding is the stable subset of a Nuclei JSONL result line that we parse
// for indexing. The full line is preserved verbatim as raw JSON alongside this,
// so unparsed fields are never lost. We intentionally keep only rock-stable
// scalar fields here to avoid unmarshal fragility across Nuclei versions.
type NucleiFinding struct {
	TemplateID string     `json:"template-id"`
	Type       string     `json:"type"`
	Host       string     `json:"host"`
	MatchedAt  string     `json:"matched-at"`
	Timestamp  string     `json:"timestamp"`
	Info       NucleiInfo `json:"info"`
}

// NucleiInfo is the nested "info" object. We read the rock-stable scalar fields
// plus tags and CVE classification, which we promote to indexed columns for
// filtering (the full line is still preserved verbatim as raw).
type NucleiInfo struct {
	Name           string                `json:"name"`
	Severity       string                `json:"severity"`
	Tags           []string              `json:"tags,omitempty"`
	Classification *NucleiClassification `json:"classification,omitempty"`
}

// NucleiClassification holds the vulnerability identifiers we index for search.
type NucleiClassification struct {
	CVEID []string `json:"cve-id,omitempty"`
	CWEID []string `json:"cwe-id,omitempty"`
}

// CVEs returns the finding's CVE ids (nil-safe).
func (f NucleiFinding) CVEs() []string {
	if f.Info.Classification == nil {
		return nil
	}
	return f.Info.Classification.CVEID
}

// NewID returns a random RFC 4122 v4 UUID string. UUID generation is a solved,
// correctness-sensitive problem, so we delegate to google/uuid rather than
// hand-roll it. Kept as a thin seam so call sites don't import the lib directly.
func NewID() string {
	return uuid.NewString()
}
