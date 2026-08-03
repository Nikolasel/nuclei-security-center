package types

import (
	"net/netip"
	"net/url"
	"strings"
)

// NormalizeTargetHost canonicalizes the case-insensitive parts of a target
// entry without changing URL paths or IP/CIDR text. URL paths, userinfo, and
// non-empty explicit ports remain part of the target identity because they can change
// the request Nuclei sends. Validation remains the backend's responsibility;
// this helper only trims and canonicalizes values.
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
		if port == "" {
			return strings.ToLower(hostPart)
		}
		if _, err := netip.ParseAddr(hostPart); err == nil {
			return host
		}
		return strings.ToLower(hostPart) + ":" + port
	}
	if _, err := netip.ParseAddrPort(host); err == nil {
		return host
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	return strings.ToLower(host)
}

// targetHostIdentity returns a canonical comparison key for IP and CIDR
// spellings. The output value itself remains the first normalized/trimmed
// representation so target text is not rewritten merely to deduplicate it.
func targetHostIdentity(host string) string {
	if prefix, err := netip.ParsePrefix(host); err == nil {
		return prefix.Masked().String()
	}
	if addrPort, err := netip.ParseAddrPort(host); err == nil {
		return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()).String()
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

// DeduplicateTargetHosts normalizes valid target entries and keeps the first
// occurrence of each one in the caller's order. IP and CIDR identity uses
// netip's canonical spelling while preserving the first entry's output text.
// It is deliberately tolerant of invalid entries because validation belongs at
// the backend API boundary.
func DeduplicateTargetHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = NormalizeTargetHost(host)
		identity := targetHostIdentity(host)
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		out = append(out, host)
	}
	return out
}
