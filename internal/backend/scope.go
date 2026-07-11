package backend

import (
	"net/netip"
	"net/url"
	"strings"
)

// Scope guardrail (Phase 3, §6 — the most important one). A scan may only target
// hosts that fall inside an approved target record; the union of all targets'
// hosts is the allowlist. This prevents fat-fingering a scan at out-of-scope or
// third-party assets, which for an active scanner is the difference between a
// tool and an incident. Enforced before dispatch on the ad-hoc spec path; the
// stored-target path is in-scope by construction.
//
// Matching is host-granular (ports and URL paths are ignored — the asset is the
// host) and never resolves DNS. In-scope means, for a scan target T and some
// approved entry A:
//   - T is an IP and A is that IP, or A is a CIDR containing it;
//   - T is a hostname and A is the same hostname (exact, case-insensitive — no
//     wildcard, so example.com does not cover sub.example.com);
//   - T is a CIDR and A is a CIDR that fully contains it.

type assetKind int

const (
	assetHost assetKind = iota // a DNS hostname (lowercased in .host)
	assetIP                    // a single IP address (.addr)
	assetCIDR                  // an IP network (.prefix)
)

type asset struct {
	kind   assetKind
	host   string
	addr   netip.Addr
	prefix netip.Prefix
}

// parseAsset classifies a host/IP/CIDR/URL string (the forms validateHost
// accepts) into a comparable asset. ok is false for input it can't classify.
func parseAsset(raw string) (asset, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return asset{}, false
	}

	// URL form: reduce to its hostname, then classify that.
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return asset{}, false
		}
		raw = u.Hostname()
	}

	// CIDR form.
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return asset{}, false
		}
		return asset{kind: assetCIDR, prefix: p.Masked()}, true
	}

	// Strip a single trailing :port (bare IPv6 keeps its colons and is parsed whole).
	host := raw
	if h, _, err := splitHostPort(raw); err == nil {
		host = h
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		return asset{kind: assetIP, addr: addr}, true
	}
	return asset{kind: assetHost, host: strings.ToLower(host)}, true
}

// inScope reports whether scan target t is covered by some approved entry.
func inScope(t asset, approved []asset) bool {
	for _, a := range approved {
		switch t.kind {
		case assetIP:
			if a.kind == assetIP && a.addr == t.addr {
				return true
			}
			if a.kind == assetCIDR && a.prefix.Contains(t.addr) {
				return true
			}
		case assetHost:
			if a.kind == assetHost && a.host == t.host {
				return true
			}
		case assetCIDR:
			// The scan subnet must sit entirely within an approved subnet: same
			// family, an equal-or-broader mask, and the network address inside it.
			if a.kind == assetCIDR &&
				a.prefix.Addr().Is4() == t.prefix.Addr().Is4() &&
				a.prefix.Bits() <= t.prefix.Bits() &&
				a.prefix.Contains(t.prefix.Addr()) {
				return true
			}
		}
	}
	return false
}

// outOfScopeHosts returns the targets not covered by the approved allowlist —
// empty means every target is in scope. A target that can't be parsed is treated
// as out of scope (fail closed). When approved is empty, everything is rejected.
func outOfScopeHosts(approved, targets []string) []string {
	parsed := make([]asset, 0, len(approved))
	for _, a := range approved {
		if pa, ok := parseAsset(a); ok {
			parsed = append(parsed, pa)
		}
	}

	var bad []string
	for _, t := range targets {
		pt, ok := parseAsset(t)
		if !ok || !inScope(pt, parsed) {
			bad = append(bad, t)
		}
	}
	return bad
}
