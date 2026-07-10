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
	t.GitRef = strings.TrimSpace(t.GitRef)
	t.Severities = trimAll(t.Severities)
	t.Tags = trimAll(t.Tags)
	t.Paths = trimAll(t.Paths)
	return nil
}

// validateSchedule trims and checks a schedule in place. The cron expression is
// validated against the same parser the ticker uses, so a schedule that saves is
// one the ticker can run. Target/template-set existence is enforced by the store
// (FK → ErrNotFound); here we only require a target_id to be present.
func validateSchedule(s *store.Schedule) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return errors.New("name is required")
	}
	s.TargetID = strings.TrimSpace(s.TargetID)
	if s.TargetID == "" {
		return errors.New("target_id is required")
	}
	s.TemplateSetID = strings.TrimSpace(s.TemplateSetID)
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
