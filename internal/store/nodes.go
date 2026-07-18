package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// ScannerNode is a registered scanner endpoint the backend dispatches to (#22).
// CIDRs are the ranges this node serves; an empty CIDRs list makes it a catch-all
// for hostname targets and IPs matching no other node. Token is the bearer token
// the backend uses to reach the node — write-only at the API layer (never
// serialized back out); the `omitempty` tag lets read paths blank it.
type ScannerNode struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Endpoint  string    `json:"endpoint"`
	Token     string    `json:"token,omitempty"`
	CIDRs     []string  `json:"cidrs"`
	Tags      []string  `json:"tags"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListScannerNodes returns all nodes ordered by name.
func (s *Store) ListScannerNodes(ctx context.Context) ([]ScannerNode, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, endpoint, token, cidrs, tags, created_by, created_at, updated_at
		 FROM scanner_nodes ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodeRows(rows)
}

// GetScannerNode returns one node by id, or ErrNotFound.
func (s *Store) GetScannerNode(ctx context.Context, id string) (ScannerNode, error) {
	n, err := scanNode(s.pool.QueryRow(ctx,
		`SELECT id, name, endpoint, token, cidrs, tags, created_by, created_at, updated_at
		 FROM scanner_nodes WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ScannerNode{}, ErrNotFound
	}
	return n, err
}

// CreateScannerNode inserts a node, rejecting a name collision (ErrConflict) or a
// CIDR overlap with an existing node (ErrNodeOverlap). The check + insert run in
// one transaction under a table lock so concurrent writers can't both slip an
// overlapping node past the check.
func (s *Store) CreateScannerNode(ctx context.Context, in ScannerNode) (ScannerNode, error) {
	in.ID = types.NewID()
	in.CIDRs = orEmpty(in.CIDRs)
	in.Tags = orEmpty(in.Tags)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ScannerNode{}, err
	}
	defer tx.Rollback(ctx)

	if err := lockAndCheckOverlap(ctx, tx, "", in.CIDRs); err != nil {
		return ScannerNode{}, err
	}
	err = tx.QueryRow(ctx,
		`INSERT INTO scanner_nodes (id, name, endpoint, token, cidrs, tags, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING created_at, updated_at`,
		in.ID, in.Name, in.Endpoint, in.Token, in.CIDRs, in.Tags, nullStr(in.CreatedBy),
	).Scan(&in.CreatedAt, &in.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ScannerNode{}, ErrConflict
		}
		return ScannerNode{}, fmt.Errorf("insert scanner node: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ScannerNode{}, err
	}
	return in, nil
}

// UpdateScannerNode updates a node's mutable fields, rejecting a name collision
// (ErrConflict) or a CIDR overlap with a *different* node (ErrNodeOverlap).
func (s *Store) UpdateScannerNode(ctx context.Context, id string, in ScannerNode) (ScannerNode, error) {
	in.CIDRs = orEmpty(in.CIDRs)
	in.Tags = orEmpty(in.Tags)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ScannerNode{}, err
	}
	defer tx.Rollback(ctx)

	if err := lockAndCheckOverlap(ctx, tx, id, in.CIDRs); err != nil {
		return ScannerNode{}, err
	}
	n, err := scanNode(tx.QueryRow(ctx,
		`UPDATE scanner_nodes SET name = $2, endpoint = $3, token = $4, cidrs = $5, tags = $6, updated_at = now()
		 WHERE id = $1
		 RETURNING id, name, endpoint, token, cidrs, tags, created_by, created_at, updated_at`,
		id, in.Name, in.Endpoint, in.Token, in.CIDRs, in.Tags))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ScannerNode{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return ScannerNode{}, ErrConflict
		}
		return ScannerNode{}, fmt.Errorf("update scanner node: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ScannerNode{}, err
	}
	return n, nil
}

// DeleteScannerNode removes a node, or returns ErrNotFound. It refuses
// (ErrLastCatchAll) to delete the only catch-all (no-CIDR) node, since hostname
// and unmatched-IP targets would then have nowhere to dispatch.
func (s *Store) DeleteScannerNode(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	nodes, err := lockAndListNodes(ctx, tx)
	if err != nil {
		return err
	}
	var target *ScannerNode
	catchAlls := 0
	for i := range nodes {
		if len(nodes[i].CIDRs) == 0 {
			catchAlls++
		}
		if nodes[i].ID == id {
			target = &nodes[i]
		}
	}
	if target == nil {
		return ErrNotFound
	}
	if len(target.CIDRs) == 0 && catchAlls == 1 {
		return ErrLastCatchAll
	}
	if _, err := tx.Exec(ctx, `DELETE FROM scanner_nodes WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SelectScannerNode picks the node to run a scan against its targets. Every
// IP/CIDR target must fall in the same node's ranges; a scan spanning two nodes
// is rejected (split it). Targets matching no node (hostnames — matching is
// DNS-free — or IPs outside every range) use a catch-all node. Returns
// ErrNoNodeForTarget when nothing matches and no catch-all exists.
func (s *Store) SelectScannerNode(ctx context.Context, targets []string) (ScannerNode, error) {
	nodes, err := s.ListScannerNodes(ctx)
	if err != nil {
		return ScannerNode{}, err
	}
	return selectNode(nodes, targets)
}

// selectNode is the pure selection logic over a node set (see SelectScannerNode).
func selectNode(nodes []ScannerNode, targets []string) (ScannerNode, error) {
	var matched *ScannerNode
	for _, t := range targets {
		ip := targetIP(t)
		if ip == nil {
			continue // hostname / non-IP → a catch-all handles it
		}
		n := nodeForIP(nodes, ip)
		if n == nil {
			continue // IP outside every node's ranges → catch-all
		}
		if matched == nil {
			matched = n
			continue
		}
		if matched.ID != n.ID {
			return ScannerNode{}, fmt.Errorf("%w: targets span nodes %q and %q; dispatch one at a time",
				ErrNoNodeForTarget, matched.Name, n.Name)
		}
	}
	if matched != nil {
		return *matched, nil
	}
	// No IP matched a specific node: use the first catch-all (deterministic —
	// nodes are name-ordered; no round-robin by design).
	for i := range nodes {
		if len(nodes[i].CIDRs) == 0 {
			return nodes[i], nil
		}
	}
	return ScannerNode{}, ErrNoNodeForTarget
}

// nodeForIP returns the node whose CIDRs contain ip, or nil. Overlaps are
// rejected on write, so at most one node can match.
func nodeForIP(nodes []ScannerNode, ip net.IP) *ScannerNode {
	for i := range nodes {
		for _, c := range nodes[i].CIDRs {
			if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && n.Contains(ip) {
				return &nodes[i]
			}
		}
	}
	return nil
}

// --- overlap checking (write path) ---

// lockAndCheckOverlap locks the table and rejects (ErrNodeOverlap) if newCIDRs
// overlap any node other than excludeID. The lock serializes concurrent writers
// so the check-then-write stays sound.
func lockAndCheckOverlap(ctx context.Context, tx pgx.Tx, excludeID string, newCIDRs []string) error {
	newNets, err := parseCIDRs(newCIDRs)
	if err != nil {
		return err
	}
	if len(newNets) == 0 {
		// Catch-all nodes (no CIDRs) can't overlap anything; still lock so the
		// insert is serialized against a concurrent range change.
		if _, err := tx.Exec(ctx, `LOCK TABLE scanner_nodes IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		return nil
	}
	nodes, err := lockAndListNodes(ctx, tx)
	if err != nil {
		return err
	}
	for i := range nodes {
		if nodes[i].ID == excludeID {
			continue
		}
		other, err := parseCIDRs(nodes[i].CIDRs)
		if err != nil {
			continue // a malformed stored CIDR can't be matched anyway
		}
		for _, a := range newNets {
			for _, b := range other {
				if a.Contains(b.IP) || b.Contains(a.IP) {
					return fmt.Errorf("%w: %s overlaps node %q (%s)", ErrNodeOverlap, a, nodes[i].Name, b)
				}
			}
		}
	}
	return nil
}

// lockAndListNodes takes the table's write lock and returns every node.
func lockAndListNodes(ctx context.Context, tx pgx.Tx) ([]ScannerNode, error) {
	if _, err := tx.Exec(ctx, `LOCK TABLE scanner_nodes IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx,
		`SELECT id, name, endpoint, token, cidrs, tags, created_by, created_at, updated_at
		 FROM scanner_nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodeRows(rows)
}

// parseCIDRs parses a node's CIDR strings into networks, erroring on a bad one.
func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", c, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// targetIP extracts an IP from a target string — a bare IP, host:port, CIDR (its
// network address), or URL. Returns nil for a hostname (matching is DNS-free,
// mirroring the scope guardrail).
func targetIP(target string) net.IP {
	s := strings.TrimSpace(target)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return net.ParseIP(s)
}

// --- row scanning ---

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanNode(row rowScanner) (ScannerNode, error) {
	var n ScannerNode
	var createdBy *string
	if err := row.Scan(&n.ID, &n.Name, &n.Endpoint, &n.Token, &n.CIDRs, &n.Tags,
		&createdBy, &n.CreatedAt, &n.UpdatedAt); err != nil {
		return ScannerNode{}, err
	}
	n.CreatedBy = deref(createdBy)
	return n, nil
}

func scanNodeRows(rows pgx.Rows) ([]ScannerNode, error) {
	var out []ScannerNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
