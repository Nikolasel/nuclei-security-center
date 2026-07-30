package types

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// EndpointKey reduces a Nuclei trace address or finding matched-at value to the
// canonical host:port identity used by lifecycle coverage. It never falls back
// to a host-only key: an unknown port is unknown coverage, because reaching a
// different service on the same machine cannot prove that this endpoint was
// rechecked (#91).
func EndpointKey(raw, protocol string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		port := parsed.Port()
		if port == "" {
			port = defaultEndpointPort(parsed.Scheme, protocol)
		}
		return canonicalEndpoint(parsed.Hostname(), port)
	}

	authority := raw
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		authority = authority[i+1:]
	}
	if host, _, err := net.SplitHostPort(authority); err == nil {
		_, port, _ := net.SplitHostPort(authority)
		return canonicalEndpoint(host, port)
	}
	if addr, err := netip.ParseAddr(strings.Trim(authority, "[]")); err == nil {
		return canonicalEndpoint(addr.String(), defaultEndpointPort("", protocol))
	}
	// An unbracketed hostname:port is common in Nuclei network results. Raw IPv6
	// was handled above, so a single remaining colon is unambiguously a port.
	if strings.Count(authority, ":") == 1 {
		host, port, _ := strings.Cut(authority, ":")
		return canonicalEndpoint(host, port)
	}
	return canonicalEndpoint(authority, defaultEndpointPort("", protocol))
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func canonicalEndpoint(host, port string) string {
	host = normalizeHost(host)
	n, err := strconv.Atoi(port)
	if host == "" || err != nil || n < 1 || n > 65535 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(n))
}

func defaultEndpointPort(scheme, protocol string) string {
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return "80"
	case "https", "wss":
		return "443"
	}
	switch strings.ToLower(protocol) {
	case "ssl", "tls":
		return "443"
	case "dns":
		return "53"
	case "whois":
		return "43"
	default:
		return ""
	}
}
