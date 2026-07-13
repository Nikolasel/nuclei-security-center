package backend

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Scanner node registry (#22). Nodes self-register (and heartbeat) their
// endpoint + zone + tags + capabilities with the backend; dispatch then picks a
// healthy node without a backend config change. The registry is in-memory and
// self-healing: entries expire after a heartbeat TTL, and nodes re-register on
// their next heartbeat after a backend restart — consistent with invariant #4
// (the node is stateless; nothing about it is a persisted system of record).
//
// Registration is node→backend metadata only; scan traffic stays strictly
// backend→node (polling). The backend authenticates a registering node with the
// shared scanner token and dispatches to it with that same token.

// Node is a registered scanner node plus liveness derived at read time.
type Node struct {
	types.NodeRegistration
	LastHeartbeat time.Time `json:"last_heartbeat"`
	Healthy       bool      `json:"healthy"`
}

// Registry tracks live scanner nodes. Safe for concurrent use.
type Registry struct {
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	nodes map[string]*types.NodeRegistration // keyed by endpoint
	beats map[string]time.Time
	rr    atomic.Uint64
}

// NewRegistry builds a registry whose nodes are considered healthy for ttl after
// their last heartbeat.
func NewRegistry(ttl time.Duration) *Registry {
	return &Registry{
		ttl:   ttl,
		now:   time.Now,
		nodes: make(map[string]*types.NodeRegistration),
		beats: make(map[string]time.Time),
	}
}

// Register upserts a node and stamps its heartbeat. Endpoint is the identity key,
// so a node that restarts with the same endpoint refreshes its entry.
func (r *Registry) Register(reg types.NodeRegistration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := reg
	r.nodes[reg.Endpoint] = &n
	r.beats[reg.Endpoint] = r.now()
}

// List returns every known node with computed liveness, for ops visibility.
func (r *Registry) List() []Node {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]Node, 0, len(r.nodes))
	for ep, reg := range r.nodes {
		beat := r.beats[ep]
		out = append(out, Node{
			NodeRegistration: *reg,
			LastHeartbeat:    beat,
			Healthy:          now.Sub(beat) <= r.ttl,
		})
	}
	return out
}

// Pick returns a healthy node for the zone (round-robin), or ok=false if none.
// An empty zone matches any healthy node; otherwise only nodes in that zone (a
// node with an empty zone is treated as a catch-all that matches any zone).
func (r *Registry) Pick(zone string) (types.NodeRegistration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var healthy []types.NodeRegistration
	for ep, reg := range r.nodes {
		if now.Sub(r.beats[ep]) > r.ttl {
			continue
		}
		if zone != "" && reg.Zone != "" && reg.Zone != zone {
			continue
		}
		healthy = append(healthy, *reg)
	}
	if len(healthy) == 0 {
		return types.NodeRegistration{}, false
	}
	// Sort for a stable ordering so the round-robin counter actually rotates
	// across nodes (map iteration order is randomized).
	sort.Slice(healthy, func(i, j int) bool { return healthy[i].Endpoint < healthy[j].Endpoint })
	i := int(r.rr.Add(1)-1) % len(healthy)
	return healthy[i], true
}
