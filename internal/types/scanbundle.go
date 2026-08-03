package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Scan bundle (#136): a self-contained, versioned representation of a complete
// scan that round-trips between deployments. Like a scan-results file (a Nessus
// .ness import into Tenable Security Center), the bundle carries **the scan's
// data**, not the exporter's globally deduplicated finding lifecycle: the
// destination re-derives the lifecycle from the imported results under its own
// rules exactly as if it had scanned the target itself. A bundle is a single
// JSON document (optionally wrapped in a zip archive as manifest.json) carrying:
//
//   - the scan record itself (timestamps, state, provenance, discovered targets,
//     covered-endpoint evidence, resolved template ids + templates commit, and
//     the verbatim dispatch spec);
//   - the resolved config that produced it (target / template set / scan policy
//     snapshots plus the reference ids on the exporting instance, so a bundle is
//     understandable standalone); and
//   - every immutable occurrence with its preserved Nuclei raw JSON — the import
//     recomputes each occurrence's dedup identity from that raw payload and
//     lets this instance's own detection-state / first-last-seen / mitigation
//     rules and analyst overlays decide the lifecycle.
//
// The format is deliberately versioned: FormatVersion is the contract; import
// rejects a bundle newer than it understands and never silently guesses.

const (
	// ScanBundleFormat is the manifest's self-describing format marker.
	ScanBundleFormat = "nuclei-security-center/scan-bundle"
	// ScanBundleFormatVersion is the current manifest version. Bump on any
	// breaking change; import accepts only <= this version.
	ScanBundleFormatVersion = 1
	// ScanBundleManifestName is the manifest file's name inside a zip bundle.
	ScanBundleManifestName = "manifest.json"
	// ScanBundleMaxUpload is the request-size ceiling for an import (raw JSON or
	// compressed zip), mirroring the orchestrator's own results-stream ceiling.
	ScanBundleMaxUpload = 512 << 20
	// ScanBundleMaxFindings caps the occurrence count an import will accept, so a
	// pathological bundle cannot exhaust backend memory while decoding.
	ScanBundleMaxFindings = 1 << 20
)

// ScanBundle is the top-level manifest of the own-format scan bundle (#136).
type ScanBundle struct {
	Format        string              `json:"format"`
	FormatVersion int                 `json:"format_version"`
	ExportedAt    time.Time           `json:"exported_at"`
	Scan          ScanBundleScan      `json:"scan"`
	Findings      []ScanBundleFinding `json:"findings"`
	Config        ScanBundleConfig    `json:"config,omitempty"`
}

// ScanBundleScan is the scan record as captured in a bundle.
type ScanBundleScan struct {
	ID                  string             `json:"id"`
	State               string             `json:"state"`
	Source              string             `json:"source,omitempty"`
	NucleiVersion       string             `json:"nuclei_version,omitempty"`
	TemplatesCommit     string             `json:"templates_commit,omitempty"`
	Error               string             `json:"error,omitempty"`
	SkippedFindingCount int                `json:"skipped_finding_count"`
	CreatedAt           time.Time          `json:"created_at"`
	StartedAt           *time.Time         `json:"started_at,omitempty"`
	FinishedAt          *time.Time         `json:"finished_at,omitempty"`
	DiscoveredTargets   []string           `json:"discovered_targets,omitempty"`
	CoveredEndpoints    []EndpointCoverage `json:"covered_endpoints"`
	CoverageWarning     string             `json:"coverage_warning,omitempty"`
	// TemplateIDs is the resolved concrete template selection the node ran. It is
	// the readable form of spec.Templates.TemplateIDs.
	TemplateIDs []string `json:"template_ids,omitempty"`
	// Spec is the verbatim dispatch spec (scans.spec JSONB) the exporter recorded,
	// preserved byte-for-byte so the bundle stays reproducible.
	Spec json.RawMessage `json:"spec,omitempty"`
}

// ScanBundleConfig captures the resolved configuration that produced the scan
// and the reference ids on the exporting instance. The ids are what import
// matches against the destination; each snapshot makes the bundle standalone.
type ScanBundleConfig struct {
	// Reference ids on the exporting instance. Empty means the scan had no such
	// link (ad-hoc, or the entity was deleted before export).
	TargetID      string `json:"target_id,omitempty"`
	TemplateSetID string `json:"template_set_id,omitempty"`
	ScanPolicyID  string `json:"scan_policy_id,omitempty"`
	NodeID        string `json:"node_id,omitempty"`
	ScheduleID    string `json:"schedule_id,omitempty"`

	Target      *TargetBundleSnapshot      `json:"target,omitempty"`
	TemplateSet *TemplateSetBundleSnapshot `json:"template_set,omitempty"`
	ScanPolicy  *ScanPolicyBundleSnapshot  `json:"scan_policy,omitempty"`
}

// TargetBundleSnapshot is the exporter's resolved target record.
type TargetBundleSnapshot struct {
	Name  string   `json:"name,omitempty"`
	Hosts []string `json:"hosts,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// TemplateSetBundleSnapshot is the exporter's resolved template set record.
type TemplateSetBundleSnapshot struct {
	Name string `json:"name,omitempty"`
	Mode string `json:"mode,omitempty"`
}

// ScanPolicyBundleSnapshot is the exporter's resolved scan policy record.
type ScanPolicyBundleSnapshot struct {
	Name          string `json:"name,omitempty"`
	TemplateSetID string `json:"template_set_id,omitempty"`
	RateLimit     *int   `json:"rate_limit,omitempty"`
	Concurrency   *int   `json:"concurrency,omitempty"`
	TimeoutSec    *int   `json:"timeout_sec,omitempty"`
	MaxHostError  *int   `json:"max_host_error,omitempty"`
	// Discovery settings (#86). DiscoveryEnabled nil means "the built-in default
	// (ON)" — mirrored from the store record.
	DiscoveryEnabled        *bool  `json:"discovery_enabled,omitempty"`
	DiscoveryScanType       string `json:"discovery_scan_type,omitempty"`
	DiscoveryPorts          string `json:"discovery_ports,omitempty"`
	DiscoveryTimeoutSec     *int   `json:"discovery_timeout_sec,omitempty"`
	DiscoveryRate           *int   `json:"discovery_rate,omitempty"`
	DiscoveryProbeTimeoutMs *int   `json:"discovery_probe_timeout_ms,omitempty"`
	DiscoveryRetries        *int   `json:"discovery_retries,omitempty"`
}

// ScanBundleFinding is one immutable occurrence with its preserved Nuclei JSON.
// ID is the occurrence id on the exporting instance (informational only —
// import links by lifecycle identity, never by numeric id).
type ScanBundleFinding struct {
	ID         int64     `json:"id"`
	TargetID   string    `json:"target_id,omitempty"`
	TemplateID string    `json:"template_id"`
	Name       string    `json:"name,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Host       string    `json:"host,omitempty"`
	MatchedAt  string    `json:"matched_at,omitempty"`
	Type       string    `json:"type,omitempty"`
	CVE        []string  `json:"cve,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	// Raw is the preserved Nuclei result (COALESCE(raw_line, raw::text)).
	// The finding lifecycle identity is re-derived from it on import; the
	// bundle carries the scan's results, never the exporter's globally
	// deduplicated lifecycle (a .ness file, not an analysis).
	Raw json.RawMessage `json:"raw,omitempty"`
}

// ErrBundleUnsupported signals a bundle this backend does not understand.
var ErrBundleUnsupported = errors.New("unsupported scan bundle")

// Validate checks a decoded bundle for structural sanity before any database
// work. It is deliberately conservative: a malformed or hostile bundle must
// fail here, not inside the import transaction.
func (b *ScanBundle) Validate() error {
	if b == nil {
		return errors.New("scan bundle is empty")
	}
	if b.Format != ScanBundleFormat {
		return fmt.Errorf("%w: format %q (want %q)", ErrBundleUnsupported, b.Format, ScanBundleFormat)
	}
	if b.FormatVersion <= 0 {
		return fmt.Errorf("scan bundle: invalid format_version %d", b.FormatVersion)
	}
	if b.FormatVersion > ScanBundleFormatVersion {
		return fmt.Errorf("%w: format_version %d is newer than this backend supports (%d)",
			ErrBundleUnsupported, b.FormatVersion, ScanBundleFormatVersion)
	}
	scan := b.Scan
	if scan.ID == "" {
		return errors.New("scan bundle: scan.id is required")
	}
	if _, err := uuid.Parse(scan.ID); err != nil {
		return fmt.Errorf("scan bundle: scan.id %q is not a UUID", scan.ID)
	}
	if scan.CreatedAt.IsZero() {
		return errors.New("scan bundle: scan.created_at is required")
	}
	switch scan.State {
	case string(ScanQueued), string(ScanRunning), string(ScanComplete), string(ScanFailed), string(ScanCancelled):
	default:
		return fmt.Errorf("scan bundle: unknown scan state %q", scan.State)
	}
	if scan.SkippedFindingCount < 0 {
		return errors.New("scan bundle: scan.skipped_finding_count cannot be negative")
	}
	if len(scan.Spec) == 0 || !json.Valid(scan.Spec) {
		return errors.New("scan bundle: scan.spec is required and must be valid JSON")
	}
	if len(b.Findings) > ScanBundleMaxFindings {
		return fmt.Errorf("scan bundle: %d findings exceeds the %d limit", len(b.Findings), ScanBundleMaxFindings)
	}
	for i, f := range b.Findings {
		if f.TemplateID == "" {
			return fmt.Errorf("scan bundle: finding %d has no template_id", i)
		}
		if f.CreatedAt.IsZero() {
			return fmt.Errorf("scan bundle: finding %d has no created_at", i)
		}
		if len(f.Raw) == 0 || !json.Valid(f.Raw) {
			return fmt.Errorf("scan bundle: finding %d has invalid or missing raw payload", i)
		}
	}
	return nil
}
