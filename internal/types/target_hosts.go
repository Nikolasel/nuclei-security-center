package types

import (
	"net/netip"
	"net/url"
	"strings"
)

// NormalizeTargetHost canonicalizes the case-insensitive parts of a target
// entry without changing URL paths or IP/CIDR text. Validation remains the
// backend's responsibility; invalid entries are returned in their trimmed form
// so callers can still report the original validation error.
func NormalizeTargetHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err == nil && u.Host != "" {
			u.Scheme = strings.ToLower(u.Scheme)
			u.Host = strings.ToLower(u.Host)
			return u.String()
		}
		return host
	}

	// Leave CIDR and bare IPv6 text unchanged. Their syntax is validated by the
	// backend, and this helper is for hostname identity rather than IP formatting.
	if strings.Contains(host, "/") {
		return host
	}
	if strings.Count(host, ":") == 1 {
		i := strings.LastIndex(host, ":")
		hostPart, port := host[:i], host[i+1:]
		if _, err := netip.ParseAddr(hostPart); err == nil {
			return host
		}
		return strings.ToLower(hostPart) + ":" + port
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	return strings.ToLower(host)
}

// DeduplicateTargetHosts normalizes valid target entries and keeps the first
// occurrence of each one in the caller's order. It is deliberately tolerant of
// invalid entries because validation belongs at the backend API boundary.
func DeduplicateTargetHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = NormalizeTargetHost(host)
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}
