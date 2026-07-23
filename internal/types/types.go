// Package types holds the wire contracts shared between the backend and the
// scanner node, plus the subset of Nuclei's JSONL output we parse for indexing.
package types

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"

	"github.com/google/uuid"
)

// ScanState is the lifecycle of a scan, tracked by both the scanner node
// (in memory, for one run) and the backend (durably, in Postgres).
type ScanState string

const (
	ScanQueued    ScanState = "queued"    // backend-only: created, not yet dispatched
	ScanRunning   ScanState = "running"   // dispatched to a node and executing
	ScanComplete  ScanState = "complete"  // finished, results ingested
	ScanFailed    ScanState = "failed"    // dispatch/run/ingest error
	ScanCancelled ScanState = "cancelled" // operator stopped it before completion
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

// ScanOptions maps to Nuclei's rate/concurrency/timeout knobs. MaxHostError is
// Nuclei's -max-host-error: how many errors a single host may accumulate (across
// every protocol, not per port) before Nuclei abandons it for the rest of the
// run. <= 0 omits the flag, so Nuclei's own default of 30 applies.
type ScanOptions struct {
	RateLimit    int `json:"rate_limit,omitempty"`
	Concurrency  int `json:"concurrency,omitempty"`
	TimeoutSec   int `json:"timeout_sec,omitempty"`
	MaxHostError int `json:"max_host_error,omitempty"`
	// Discovery, when non-nil and Enabled, runs a naabu port-scan pre-pass on the
	// node before Nuclei, so Nuclei only probes live host:port pairs (#86). nil or
	// Enabled=false ⇒ Nuclei scans every host unfiltered (the pre-policy behavior).
	Discovery *DiscoveryOptions `json:"discovery,omitempty"`
}

// DiscoveryOptions configures the optional naabu port-discovery stage (#86). It
// runs entirely on the scanner node before Nuclei — the node stays stateless and
// credential-less; the backend only sets these knobs from the scan policy. The
// stage FAILS CLOSED: any naabu error aborts the scan (rather than falling back
// to an unfiltered run), so a misconfigured discovery is disabled deliberately on
// the policy, never silently ignored.
type DiscoveryOptions struct {
	Enabled bool `json:"enabled"`
	// ScanType picks naabu's scan mode: "syn" (SYN + host discovery, needs the
	// node's CAP_NET_RAW + libpcap) or "connect" (unprivileged, no host discovery).
	// Empty ⇒ the node's own NAABU_SCAN_TYPE default. Requesting "syn" on a node
	// without raw-socket capability fails the scan closed (#86).
	ScanType string `json:"scan_type,omitempty"`
	// Ports is naabu's -port spec (e.g. "80,443,8000-9000", multiple ranges
	// allowed). Empty ⇒ naabu's top-1000 ports (the nmap top-1000 set).
	Ports string `json:"ports,omitempty"`
	// TimeoutSec is discovery's OWN time budget, separate from the scan's
	// Nuclei TimeoutSec. <= 0 ⇒ the node's built-in discovery default.
	TimeoutSec int `json:"timeout_sec,omitempty"`
	// naabu tuning knobs (all <= 0 ⇒ naabu's own default). These trade speed for
	// completeness — lower per-probe timeout / retries finish faster on sparse or
	// dense ranges but can miss slow-responding or (for SYN) lossy ports.
	Rate           int `json:"rate,omitempty"`             // -rate: packets/sec (default 1000)
	ProbeTimeoutMs int `json:"probe_timeout_ms,omitempty"` // -timeout: ms per probe (default 1000)
	Retries        int `json:"retries,omitempty"`          // -retries: probe retries (default 3)
}

// ScanStatus is the response from GET /v1/scans/{id} on the scanner node.
type ScanStatus struct {
	ID              string        `json:"id"`
	State           ScanState     `json:"state"`
	NucleiVersion   string        `json:"nuclei_version,omitempty"`
	TemplatesCommit string        `json:"templates_commit,omitempty"`
	FindingCount    int           `json:"finding_count"`
	Error           string        `json:"error,omitempty"`
	Progress        *ScanProgress `json:"progress,omitempty"`
	// DiscoveredTargets is the narrowed host:port list the naabu pre-pass (#86)
	// produced and handed to Nuclei. Reported once discovery completes and kept for
	// the scan's life on the node; the backend persists it so the UI can show which
	// endpoints were actually scanned. Empty when discovery was disabled.
	DiscoveredTargets []string `json:"discovered_targets,omitempty"`
}

// ScanPhase distinguishes the two execution stages the node reports live progress
// for (#86). Empty means the single-stage (Nuclei-only) case.
type ScanPhase string

const (
	PhaseDiscovering ScanPhase = "discovering" // naabu port pre-pass
	PhaseScanning    ScanPhase = "scanning"    // Nuclei
)

// Capabilities is the response from GET /v1/capabilities on the scanner node —
// the runtime facts only the node knows, polled by the backend to derive node
// liveness (#98). Zone/CIDRs/tags are NOT here: those live in the backend's node
// registry, not on the (stateless) node. TemplatesCommit is the digest of the
// template bundle the node currently has active (empty if none applied yet).
type Capabilities struct {
	NucleiVersion   string `json:"nuclei_version,omitempty"`
	TemplatesCommit string `json:"templates_commit,omitempty"`
}

// TemplateBundleEntry is one template inside a bundle's manifest (#85). SHA256 is
// the hex sha256 of the template's YAML bytes — the same content hash the catalog
// stores — so the node can verify each extracted file byte-for-byte.
type TemplateBundleEntry struct {
	ID     string `json:"id"`
	Path   string `json:"path"`   // bundle-relative path, e.g. "http/cves/2021/CVE-2021-44228.yaml"
	SHA256 string `json:"sha256"` // hex sha256 of the file's YAML bytes
}

// TemplateBundleManifest is manifest.json at the root of a bundle tarball. The
// backend builds it from a resolved template set; the node verifies every listed
// file is present with the right hash and that Digest matches BundleDigest.
type TemplateBundleManifest struct {
	Digest    string                `json:"digest"` // canonical digest, == BundleDigest(Templates)
	Templates []TemplateBundleEntry `json:"templates"`
}

// TemplateBundleStatus is the node's response to POST /v1/templates/bundle after
// it verifies and activates a bundle. TemplatesCommit is the activated digest —
// the value a subsequent scan records as its templates_commit for reproducibility.
type TemplateBundleStatus struct {
	TemplatesCommit string `json:"templates_commit"`
	TemplateCount   int    `json:"template_count"`
}

// BundleDigest computes a bundle's canonical, order-independent digest: the
// sha256 over each template's "id\x00sha256\n" line, sorted by id. It is content-
// addressed — independent of tar byte order, file timestamps, and compression —
// so the backend and node derive the identical value from the same set of
// templates, and it becomes the scan's templates_commit. Duplicate or empty ids
// are the caller's concern; this hashes exactly what it is given.
func BundleDigest(entries []TemplateBundleEntry) string {
	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = e.ID + "\x00" + e.SHA256 + "\n"
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		_, _ = io.WriteString(h, l)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ScanProgress is a live snapshot of a running scan's progress, parsed from
// Nuclei's periodic -stats-json output on the scanner node (#66). It is
// ephemeral/in-memory — never persisted (the node is stateless per run; the
// backend caches the latest snapshot only while the scan runs). Percent is the
// most useful signal (Nuclei's own completion estimate, request-based); the
// counts contextualize it. All fields are best-effort — an omitted stats field
// stays zero.
type ScanProgress struct {
	// Phase is which stage this snapshot describes: "discovering" (naabu) or
	// "scanning" (Nuclei). The Nuclei fields below are meaningful in the scanning
	// phase; the Disc* fields in the discovering phase. Empty for legacy callers.
	Phase    ScanPhase `json:"phase,omitempty"`
	Percent  float64   `json:"percent"`
	Requests int64     `json:"requests,omitempty"`
	Total    int64     `json:"total,omitempty"`
	Hosts    int64     `json:"hosts,omitempty"`
	RPS      int64     `json:"rps,omitempty"`
	Matched  int64     `json:"matched,omitempty"`
	// DiscHosts/DiscPorts are the discovering-phase live tally: hosts found with at
	// least one open port, and total open ports found so far. naabu exposes no
	// usable live stats feed, so these are counted from its own "Found N ports on
	// host X" log lines — a per-host signal, not a percentage (dead hosts emit no
	// line), which is why the discovery bar is animated rather than proportional.
	DiscHosts int `json:"disc_hosts,omitempty"`
	DiscPorts int `json:"disc_ports,omitempty"`
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
