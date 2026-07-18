package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Scanner node config seeding (#22). The DB (scanner_nodes) is the system of
// record for the scanner registry; config (SCANNER_URL + SCAN_ZONES) is only a
// bootstrap that seeds the table on first boot. After that the admin manages
// nodes via the API/UI, and the seed never re-clobbers a stored node: a config
// entry is inserted only when its name is not already present.

// ScanZoneConfig is the config form of a scanner node: a name, the CIDR ranges it
// serves, and the endpoint + token that reaches it. (Kept as the SCAN_ZONES wire
// shape for backward compatibility — a "zone" and a "node" are one entity.)
type ScanZoneConfig struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
	URL   string   `json:"url"`
	Token string   `json:"token"`
}

// SeedScannerNodes seeds the scanner_nodes table from config on startup. The
// default node (SCANNER_URL/SCANNER_TOKEN, no CIDRs — the catch-all) plus each
// SCAN_ZONES entry is inserted only when its name is absent from the DB. Within
// the config itself, a bad CIDR / duplicate name / cross-entry CIDR overlap is a
// fail-fast error (returned). Against the DB, a config entry whose CIDRs overlap
// an existing (e.g. admin-created) node is skipped with a warning so a stale file
// can never block startup; a config entry that differs from its stored row logs a
// drift note (the DB wins).
func SeedScannerNodes(ctx context.Context, st *store.Store, defaultURL, defaultToken, zonesJSON string, log *slog.Logger) error {
	desired, err := parseNodeConfig(defaultURL, defaultToken, zonesJSON)
	if err != nil {
		return err
	}

	existing, err := st.ListScannerNodes(ctx)
	if err != nil {
		return fmt.Errorf("seed scanner nodes: list existing: %w", err)
	}
	byName := make(map[string]store.ScannerNode, len(existing))
	for _, n := range existing {
		byName[n.Name] = n
	}

	seeded := 0
	for _, d := range desired {
		if cur, ok := byName[d.Name]; ok {
			if nodeDiffersFromConfig(cur, d) {
				log.Warn("scanner node config differs from stored node; DB is source of truth (edit via the API to change it)", "node", d.Name)
			}
			continue
		}
		if _, err := st.CreateScannerNode(ctx, d); err != nil {
			if errors.Is(err, store.ErrNodeOverlap) || errors.Is(err, store.ErrConflict) {
				log.Warn("skipping config scanner node that conflicts with an existing node", "node", d.Name, "err", err)
				continue
			}
			return fmt.Errorf("seed scanner node %q: %w", d.Name, err)
		}
		seeded++
	}
	if seeded > 0 {
		log.Info("seeded scanner nodes from config", "count", seeded)
	}
	return nil
}

// parseNodeConfig builds the desired node set from config and validates it in
// isolation (names unique, CIDRs parse, no cross-entry overlap) — a fail-fast
// contract mirroring the old BuildDispatcher.
func parseNodeConfig(defaultURL, defaultToken, zonesJSON string) ([]store.ScannerNode, error) {
	nodes := []store.ScannerNode{{
		Name:     "default",
		Endpoint: defaultURL,
		Token:    defaultToken,
		CIDRs:    []string{},
	}}

	if strings.TrimSpace(zonesJSON) != "" {
		var cfgs []ScanZoneConfig
		if err := json.Unmarshal([]byte(zonesJSON), &cfgs); err != nil {
			return nil, fmt.Errorf("SCAN_ZONES: invalid JSON: %w", err)
		}
		for _, c := range cfgs {
			name := strings.TrimSpace(c.Name)
			if name == "" {
				return nil, fmt.Errorf("SCAN_ZONES: a zone is missing a name")
			}
			if name == "default" {
				return nil, fmt.Errorf("SCAN_ZONES: %q is reserved for SCANNER_URL", name)
			}
			if c.URL == "" || c.Token == "" {
				return nil, fmt.Errorf("SCAN_ZONES: zone %q needs a url and token", name)
			}
			cidrs := make([]string, 0, len(c.CIDRs))
			for _, cidr := range c.CIDRs {
				cidrs = append(cidrs, strings.TrimSpace(cidr))
			}
			nodes = append(nodes, store.ScannerNode{
				Name:     name,
				Endpoint: c.URL,
				Token:    c.Token,
				CIDRs:    cidrs,
			})
		}
	}

	if err := validateNodeConfig(nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

// validateNodeConfig rejects duplicate names, bad CIDRs, and cross-node overlaps
// within the config set (fail fast at startup).
func validateNodeConfig(nodes []store.ScannerNode) error {
	seen := map[string]bool{}
	parsed := make([][]*net.IPNet, len(nodes))
	for i, n := range nodes {
		if seen[n.Name] {
			return fmt.Errorf("SCAN_ZONES: duplicate zone name %q", n.Name)
		}
		seen[n.Name] = true
		for _, cidr := range n.CIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("SCAN_ZONES: zone %q: bad CIDR %q: %w", n.Name, cidr, err)
			}
			parsed[i] = append(parsed[i], ipnet)
		}
	}
	for i := range parsed {
		for j := i + 1; j < len(parsed); j++ {
			for _, a := range parsed[i] {
				for _, b := range parsed[j] {
					if a.Contains(b.IP) || b.Contains(a.IP) {
						return fmt.Errorf("SCAN_ZONES: zones %q (%s) and %q (%s) have overlapping CIDRs", nodes[i].Name, a, nodes[j].Name, b)
					}
				}
			}
		}
	}
	return nil
}

// nodeDiffersFromConfig reports whether a stored node's endpoint/token/CIDRs
// diverge from what config would seed — used only to surface a drift warning.
func nodeDiffersFromConfig(stored store.ScannerNode, cfg store.ScannerNode) bool {
	return stored.Endpoint != cfg.Endpoint ||
		stored.Token != cfg.Token ||
		!sameStringSet(stored.CIDRs, cfg.CIDRs)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
