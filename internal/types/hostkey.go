package types

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// HostKey reduces a Nuclei input or matched-at value to the host-level identity
// used by lifecycle coverage. Schemes, credentials, ports, paths, queries, and
// fragments do not change the asset host. DNS names are case-insensitive and IP
// literals are rendered canonically.
func HostKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		return normalizeHost(parsed.Hostname())
	}

	authority := raw
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		authority = authority[i+1:]
	}
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return normalizeHost(host)
	}
	if addr, err := netip.ParseAddr(strings.Trim(authority, "[]")); err == nil {
		return addr.String()
	}
	// An unbracketed hostname:port is common in Nuclei network results. Raw IPv6
	// was handled above, so a single remaining colon is unambiguously a port.
	if strings.Count(authority, ":") == 1 {
		authority, _, _ = strings.Cut(authority, ":")
	}
	return normalizeHost(authority)
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
