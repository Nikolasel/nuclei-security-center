// Package types holds the wire contracts shared between the backend and the
// scanner node, plus the subset of Nuclei's JSONL output we parse for indexing.
package types

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"time"

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

// ScanSpec is the request body for POST /v1/scans on the scanner node. Runtime
// inputs are explicit; template ids resolve against TemplatesCommit in the
// node's already-active full-catalog bundle.
type ScanSpec struct {
	Targets            []string         `json:"targets"`
	Templates          TemplateSelector `json:"templates"`
	Options            ScanOptions      `json:"options"`
	MaxConcurrentScans int              `json:"max_concurrent_scans,omitempty"`
}

// Scan admission defaults and the hard ceiling shared by the backend registry,
// admin API, and scanner-node wire contract. The per-node setting is persisted in
// scanner_nodes; a zero wire value means the node's local fallback applies.
const (
	DefaultMaxConcurrentScans = 20
	MaxConcurrentScansCeiling = 100
)

// TemplateSelector picks which templates run. TemplateIDs select entries from
// the full catalog bundle already active on the scanner node; TemplatesCommit is
// that bundle's canonical digest, making a scan reproducible as (ids, commit).
type TemplateSelector struct {
	TemplateIDs     []string `json:"template_ids,omitempty"`
	TemplatesCommit string   `json:"templates_commit,omitempty"`
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
	// ResponseSizeRead caps bytes read into memory per request (nuclei
	// -response-size-read / -rsr, default 10 MiB). ResponseSizeSave caps bytes kept
	// for the output event (-response-size-save / -rss, default 1 MiB). <= 0 omits
	// the flag, so nuclei's own default applies (#274).
	ResponseSizeRead int `json:"response_size_read,omitempty"`
	ResponseSizeSave int `json:"response_size_save,omitempty"`
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
	// ScanType picks naabu's port-scan mode: "syn" (needs the node's CAP_NET_RAW
	// + libpcap) or "connect" (unprivileged). Empty ⇒ the node's own
	// NAABU_SCAN_TYPE default. Requesting "syn" on a node without raw-socket
	// capability fails the scan closed (#86). Host discovery is controlled
	// independently by HostDiscovery below.
	ScanType string `json:"scan_type,omitempty"`
	// HostDiscovery controls whether naabu runs its separate host-discovery pass
	// before the port scan. nil preserves the existing mode-dependent default:
	// enabled for SYN and disabled for connect. A non-nil value applies to either
	// scan type, so connect can opt into host discovery and SYN can skip it (#133).
	HostDiscovery *bool `json:"host_discovery,omitempty"`
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
	// CoveredEndpoints is the deduplicated (template id, canonical host:port)
	// evidence for successful Nuclei requests. nil means telemetry is unavailable
	// and must fail closed; an empty non-nil slice means known zero coverage.
	CoveredEndpoints []EndpointCoverage `json:"covered_endpoints"`
	CoverageWarning  string             `json:"coverage_warning,omitempty"`
}

// EndpointCoverage proves that one concrete template successfully issued a
// request to one concrete network endpoint during a scan (#91).
type EndpointCoverage struct {
	TemplateID string `json:"template_id"`
	Endpoint   string `json:"endpoint"`
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
// backend builds it from the full active catalog (upstream + custom) — a node
// holds the whole catalog and a scan later selects by id, rather than the backend
// re-streaming a per-scan subset. The node verifies every listed file is present
// with the right hash and that Digest matches BundleDigest; the manifest also
// gives the node its id→path index for per-scan template selection.
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

// TemplateValidationResult is the scanner node's authoritative verdict for one
// custom template. Errors contains bounded, human-readable Nuclei diagnostics;
// the YAML itself is never echoed back. NucleiVersion identifies the exact
// engine that produced the verdict.
type TemplateValidationResult struct {
	Valid         bool     `json:"valid"`
	Errors        []string `json:"errors"`
	NucleiVersion string   `json:"nuclei_version"`
}

// Batch validation has three nested deadlines. Keeping them together makes the
// required ordering explicit across the node, backend client, and import
// handler: a node gets two minutes, transport gets ten seconds of grace, and an
// import permits two complete healthy-node attempts plus final response grace.
const (
	TemplateBatchValidationNodeTimeout    = 2 * time.Minute
	TemplateBatchValidationClientTimeout  = TemplateBatchValidationNodeTimeout + 10*time.Second
	TemplateBatchValidationMaxAttempts    = 2
	TemplateBatchValidationRequestTimeout = time.Duration(TemplateBatchValidationMaxAttempts)*TemplateBatchValidationClientTimeout + 10*time.Second
)

// TemplateValidationFailure is the bounded Nuclei diagnostic for one template
// in a batch. TemplateID comes from the verified bundle manifest, never from
// parsing Nuclei's human-readable text.
type TemplateValidationFailure struct {
	TemplateID string   `json:"template_id"`
	Errors     []string `json:"errors"`
}

// TemplateBatchValidationResult is the verdict for one transient bundle
// validated by a single Nuclei process. Errors holds diagnostics that could not
// be attributed to one manifest entry; Failures holds per-template diagnostics.
type TemplateBatchValidationResult struct {
	Valid         bool                        `json:"valid"`
	Failures      []TemplateValidationFailure `json:"failures"`
	Errors        []string                    `json:"errors"`
	Truncated     bool                        `json:"truncated,omitempty"`
	NucleiVersion string                      `json:"nuclei_version"`
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
// for indexing. The full line is retained as raw JSON alongside this (and
// byte-exact in the per-scan archive), so unparsed fields are never lost here.
// We intentionally keep only rock-stable
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
// filtering (the full line is still retained as raw).
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
