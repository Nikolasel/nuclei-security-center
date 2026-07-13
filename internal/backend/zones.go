package backend

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Scan zones (#15). A zone maps a set of CIDR ranges to the scanner node that
// has network line-of-sight to that segment (the Tenable "scan zone" model).
// Dispatch picks the node whose zone contains the target's hosts, so a scan of
// an internal range runs on a node that can actually reach it. The scanner
// boundary is unchanged: each zone still holds only an endpoint + bearer token,
// traffic stays one-way backend→node, and the node holds no DB credentials.
//
// Zones are static backend configuration for now (env-driven); self-registration
// into a dynamic registry is the follow-up (#22).

// ScanZoneConfig is the wire/config form of a zone: a name, the CIDR ranges it
// serves, and the node endpoint + token that reaches them.
type ScanZoneConfig struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
	URL   string   `json:"url"`
	Token string   `json:"token"`
}

// zone is a compiled zone: parsed CIDRs plus a ready scanner client.
type zone struct {
	name   string
	nets   []*net.IPNet
	client *ScannerClient
}

// Dispatcher routes a scan to the scanner client whose zone matches the scan's
// targets, falling back to a default (catch-all) zone. It is safe for concurrent
// use — all state is immutable after construction.
type Dispatcher struct {
	zones []zone
	def   zone // catch-all: used when no zone CIDR matches the targets
}

// NewDispatcher builds a zone router. def is the fallback zone (the single-node
// setup's only zone), used for targets that fall in no configured zone CIDR
// (including hostname targets, which are DNS-free here and so unroutable by IP).
func NewDispatcher(zones []zone, def zone) *Dispatcher {
	return &Dispatcher{zones: zones, def: def}
}

// BuildDispatcher assembles a Dispatcher from configuration. The default zone is
// always present (from the base SCANNER_URL/SCANNER_TOKEN), preserving the
// single-node behavior when no zones are configured. Additional zones come from
// a JSON array (SCAN_ZONES). Each zone's token authenticates to its own node.
func BuildDispatcher(zonesJSON, defaultURL, defaultToken string) (*Dispatcher, error) {
	def := zone{name: "default", client: NewScannerClient(defaultURL, defaultToken)}
	if strings.TrimSpace(zonesJSON) == "" {
		return NewDispatcher(nil, def), nil
	}
	var cfgs []ScanZoneConfig
	if err := json.Unmarshal([]byte(zonesJSON), &cfgs); err != nil {
		return nil, fmt.Errorf("SCAN_ZONES: invalid JSON: %w", err)
	}
	zones := make([]zone, 0, len(cfgs))
	seen := map[string]bool{}
	for _, c := range cfgs {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return nil, fmt.Errorf("SCAN_ZONES: a zone is missing a name")
		}
		if seen[name] {
			return nil, fmt.Errorf("SCAN_ZONES: duplicate zone name %q", name)
		}
		seen[name] = true
		if c.URL == "" || c.Token == "" {
			return nil, fmt.Errorf("SCAN_ZONES: zone %q needs a url and token", name)
		}
		nets := make([]*net.IPNet, 0, len(c.CIDRs))
		for _, cidr := range c.CIDRs {
			_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				return nil, fmt.Errorf("SCAN_ZONES: zone %q: bad CIDR %q: %w", name, cidr, err)
			}
			nets = append(nets, n)
		}
		zones = append(zones, zone{name: name, nets: nets, client: NewScannerClient(c.URL, c.Token)})
	}
	return NewDispatcher(zones, def), nil
}

// ClientFor selects the scanner client for a scan's targets. Every target that
// resolves to an IP/CIDR must fall in the same zone; a scan that spans zones is
// rejected (an operator should split it). Targets that match no zone (hostnames,
// or IPs outside every zone CIDR) use the default zone. Returns the client and
// the chosen zone name.
func (d *Dispatcher) ClientFor(targets []string) (*ScannerClient, string, error) {
	matched := ""
	for _, t := range targets {
		z, ok := d.zoneFor(t)
		if !ok {
			continue // hostname or outside every zone → default handles it
		}
		if matched == "" {
			matched = z
			continue
		}
		if matched != z {
			return nil, "", fmt.Errorf("targets span multiple scan zones (%s and %s); dispatch one zone at a time", matched, z)
		}
	}
	if matched == "" {
		return d.def.client, d.def.name, nil
	}
	for i := range d.zones {
		if d.zones[i].name == matched {
			return d.zones[i].client, matched, nil
		}
	}
	// Unreachable: matched came from d.zones.
	return d.def.client, d.def.name, nil
}

// Clients returns every distinct scanner client the dispatcher can route to
// (the default zone plus each configured zone). Used for fan-out operations like
// cancel, where the node running a given scan isn't known from its id alone.
func (d *Dispatcher) Clients() []*ScannerClient {
	clients := make([]*ScannerClient, 0, len(d.zones)+1)
	clients = append(clients, d.def.client)
	for i := range d.zones {
		clients = append(clients, d.zones[i].client)
	}
	return clients
}

// zoneFor returns the zone name whose CIDRs contain the target's IP, if the
// target is an IP/CIDR that lands in a configured zone.
func (d *Dispatcher) zoneFor(target string) (string, bool) {
	ip := targetIP(target)
	if ip == nil {
		return "", false
	}
	for i := range d.zones {
		for _, n := range d.zones[i].nets {
			if n.Contains(ip) {
				return d.zones[i].name, true
			}
		}
	}
	return "", false
}

// targetIP extracts an IP from a target string — a bare IP, host:port, CIDR
// (its network address), or URL. Returns nil for a hostname (zone matching is
// DNS-free, mirroring the scope guardrail).
func targetIP(target string) net.IP {
	s := strings.TrimSpace(target)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// CIDR: match on its network address.
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip
	}
	// Strip a URL path, then an optional port.
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return net.ParseIP(s)
}
