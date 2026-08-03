package types

import (
	"math"
	"math/big"
	"net/netip"
	"strings"
)

// maxHostCount caps HostCount's return value at the largest representable
// int64. Nobody scans an entire IPv6 /0, but the arithmetic to get there is
// otherwise exact (via math/big) all the way up — this cap only exists so the
// function can never overflow or return a negative number for a pathological
// input.
const maxHostCount = math.MaxInt64

// HostCount returns how many addresses hosts represents in total. A plain
// hostname, IP, or URL counts as one; a CIDR entry counts as the full size of
// its address range (e.g. "10.0.0.0/24" is 256), computed exactly via
// math/big so a large IPv6 block can't silently wrap a fixed-width integer.
// Duplicate entries count once after target-host normalization. Unparseable
// entries (a bare hostname, a URL, garbage input) count as one — this is a
// sizing helper for display, not a validator; validateHost is the source of
// truth for whether an entry is well-formed.
func HostCount(hosts []string) int64 {
	max := big.NewInt(maxHostCount)
	total := new(big.Int)
	for _, h := range DeduplicateTargetHosts(hosts) {
		total.Add(total, cidrSize(strings.TrimSpace(h)))
		if total.Cmp(max) >= 0 {
			return maxHostCount
		}
	}
	return total.Int64()
}

// cidrSize returns 2^(host bits) for a CIDR entry (32-prefix for IPv4,
// 128-prefix for IPv6), or 1 for anything that isn't CIDR notation.
func cidrSize(h string) *big.Int {
	p, err := netip.ParsePrefix(h)
	if err != nil {
		return big.NewInt(1)
	}
	hostBits := p.Addr().BitLen() - p.Bits()
	return new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
}
