package backend

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// hostnameRe matches DNS hostnames: dot-separated labels of alphanumerics and
// hyphens, no leading/trailing hyphen per label.
var hostnameRe = regexp.MustCompile(
	`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// validateTarget trims and checks a target in place. Every host must be a
// plausible hostname, IP, CIDR, or URL — this list is the scope allowlist, so
// garbage here would mean scanning garbage.
func validateTarget(t *store.Target) error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		return errors.New("name is required")
	}
	if len(t.Hosts) == 0 {
		return errors.New("at least one host is required")
	}
	for i, h := range t.Hosts {
		h = strings.TrimSpace(h)
		if err := validateHost(h); err != nil {
			return fmt.Errorf("host %q: %w", h, err)
		}
		t.Hosts[i] = h
	}
	t.Tags = trimAll(t.Tags)
	return nil
}

// validateTemplateSet trims and checks a template set in place.
func validateTemplateSet(t *store.TemplateSet) error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		return errors.New("name is required")
	}
	if t.Mode == "" {
		t.Mode = store.TemplateSetModeExact
	}
	switch t.Mode {
	case store.TemplateSetModeExact, store.TemplateSetModeAll, store.TemplateSetModeExclude:
	default:
		return errors.New(`mode must be "exact", "all", or "exclude"`)
	}
	if t.Mode != store.TemplateSetModeExclude && len(t.ExcludedTemplateIDs) > 0 {
		return errors.New("excluded_template_ids are only allowed for mode=exclude template sets")
	}
	for i, id := range t.ExcludedTemplateIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return errors.New("excluded_template_ids cannot contain empty ids")
		}
		t.ExcludedTemplateIDs[i] = id
	}
	return nil
}

// validateScanPolicy trims and checks a scan policy in place. A policy is the
// target-independent HOW-to-scan config, so it must name a template set.
// "All templates" is represented by an explicit all-mode set, never an omitted
// reference. Their existence is enforced by the store (FK → ErrInvalidRef).
// Every execution knob is optional
// (nil = built-in default), but any knob that IS set must be positive — a
// zero/negative value is meaningless and would either be silently dropped by
// buildArgs (<= 0 omits the flag) or produce a nonsensical scan.
func validateScanPolicy(p *store.ScanPolicy) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return errors.New("name is required")
	}
	p.TemplateSetID = strings.TrimSpace(p.TemplateSetID)
	if p.TemplateSetID == "" {
		return errors.New("template_set_id is required")
	}
	for _, f := range []struct {
		name string
		val  *int
	}{
		{"rate_limit", p.RateLimit},
		{"concurrency", p.Concurrency},
		{"timeout_sec", p.TimeoutSec},
		{"max_host_error", p.MaxHostError},
		{"discovery_timeout_sec", p.DiscoveryTimeoutSec},
		{"discovery_rate", p.DiscoveryRate},
		{"discovery_probe_timeout_ms", p.DiscoveryProbeTimeoutMs},
		{"discovery_retries", p.DiscoveryRetries},
	} {
		if f.val != nil && *f.val <= 0 {
			return fmt.Errorf("%s must be positive when set", f.name)
		}
	}
	// Discovery scan type (#86) — "syn" or "connect", or empty for the node's
	// NAABU_SCAN_TYPE default. Lower-cased so the UI/API can be lenient; the DB
	// CHECK constraint is the backstop.
	p.DiscoveryScanType = strings.ToLower(strings.TrimSpace(p.DiscoveryScanType))
	switch p.DiscoveryScanType {
	case "", "syn", "connect":
	default:
		return fmt.Errorf("discovery_scan_type must be \"syn\" or \"connect\"")
	}
	// Discovery ports (#86) — validate the naabu -port spec at save time so a
	// typo fails here (friendly) rather than at scan time (discovery fails closed,
	// which would abort the whole scan). Empty = naabu's top-1000 default.
	p.DiscoveryPorts = strings.TrimSpace(p.DiscoveryPorts)
	if err := validatePortSpec(p.DiscoveryPorts); err != nil {
		return err
	}
	return nil
}

// validatePortSpec checks a naabu-style port spec: comma-separated tokens, each a
// single port (N) or an inclusive range (N-M), all within 1-65535. Empty is valid
// (means "use the default port set"). Kept intentionally strict — naabu accepts a
// few exotic forms we don't expose, and rejecting them here is friendlier than a
// failed-closed scan.
func validatePortSpec(spec string) error {
	if spec == "" {
		return nil
	}
	parsePort := func(s string) (int, error) {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("discovery_ports: %q is not a valid port (1-65535)", s)
		}
		return n, nil
	}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return errors.New("discovery_ports: empty port entry")
		}
		lo, hi, isRange := strings.Cut(tok, "-")
		start, err := parsePort(lo)
		if err != nil {
			return err
		}
		if !isRange {
			continue
		}
		end, err := parsePort(hi)
		if err != nil {
			return err
		}
		if end < start {
			return fmt.Errorf("discovery_ports: range %q is inverted", tok)
		}
	}
	return nil
}

// validateSchedule trims and checks a schedule in place. A schedule pairs an
// approved target with a reusable policy and cadence (#137). The cron expression
// is validated against the same parser the ticker uses. FK existence checks live
// in the store; here both ids are required and normalized.
func validateSchedule(s *store.Schedule) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return errors.New("name is required")
	}
	s.ScanPolicyID = strings.TrimSpace(s.ScanPolicyID)
	if s.ScanPolicyID == "" {
		return errors.New("scan_policy_id is required")
	}
	s.TargetID = strings.TrimSpace(s.TargetID)
	if s.TargetID == "" {
		return errors.New("target_id is required")
	}
	s.Cron = strings.TrimSpace(s.Cron)
	if s.Cron == "" {
		return errors.New("cron is required")
	}
	if _, err := parseCron(s.Cron); err != nil {
		return fmt.Errorf("invalid cron %q: %w", s.Cron, err)
	}
	return nil
}

// validateHost accepts a hostname, IP, CIDR, or URL (each optionally with a
// port for the host/IP forms).
func validateHost(h string) error {
	if h == "" {
		return errors.New("empty")
	}
	if strings.ContainsAny(h, " \t\r\n") {
		return errors.New("contains whitespace")
	}

	// URL form, e.g. https://example.com/path
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil || u.Host == "" {
			return errors.New("invalid URL")
		}
		return nil
	}

	// CIDR form, e.g. 10.0.0.0/24
	if strings.Contains(h, "/") {
		if _, err := netip.ParsePrefix(h); err != nil {
			return errors.New("invalid CIDR")
		}
		return nil
	}

	// Bare IP or hostname, optionally host:port.
	host := h
	if hostPart, port, err := splitHostPort(h); err == nil {
		host = hostPart
		if port != "" {
			if p, perr := strconv.Atoi(port); perr != nil || p < 1 || p > 65535 {
				return errors.New("invalid port")
			}
		}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if hostnameRe.MatchString(host) {
		return nil
	}
	return errors.New("not a valid hostname, IP, CIDR, or URL")
}

// splitHostPort separates a trailing :port only when it's unambiguous (exactly
// one colon). Bare IPv6 (multiple colons) is left intact for ParseAddr.
func splitHostPort(h string) (host, port string, err error) {
	if strings.Count(h, ":") != 1 {
		return "", "", errors.New("no single-colon port")
	}
	i := strings.LastIndex(h, ":")
	return h[:i], h[i+1:], nil
}

// trimAll trims whitespace and drops empty entries, returning a non-nil slice.
func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
