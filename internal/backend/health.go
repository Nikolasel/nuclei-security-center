package backend

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// HealthMonitor derives scanner node liveness by polling each registered node's
// GET /v1/capabilities on an interval (#98). It keeps traffic strictly
// backend→node and holds no persisted state: liveness is ephemeral and
// recomputed from the last poll (invariant #4, like scan progress). A node is
// healthy while a poll has succeeded within the TTL; a node that stops responding
// ages out to unhealthy after the TTL.
type HealthMonitor struct {
	store    *store.Store
	interval time.Duration
	ttl      time.Duration
	log      *slog.Logger
	now      func() time.Time

	mu     sync.Mutex
	health map[string]nodeHealth // keyed by node id
}

// nodeHealth is the per-node poll record. LastSeen is the last *successful* poll
// (zero = never succeeded); the entry existing at all means the node has been
// polled at least once ("known"). LastErr is the most recent poll failure's
// message (cleared on success), so the UI can show *why* a node is unhealthy
// (e.g. a 401 from a wrong token vs. an unreachable endpoint).
type nodeHealth struct {
	LastSeen time.Time
	Caps     types.Capabilities
	LastErr  string
}

// NodeHealth is the read-side view of a node's liveness for the API.
type NodeHealth struct {
	Healthy      bool
	LastSeen     time.Time
	Capabilities types.Capabilities
	LastError    string
}

// pollTimeout bounds a single node's capability poll so one hung node can't stall
// the cycle.
const pollTimeout = 5 * time.Second

// NewHealthMonitor builds a monitor polling every interval. A node is healthy if
// a poll succeeded within 3× the interval (tolerating two missed polls before it
// flips), so the TTL scales with the configured cadence.
func NewHealthMonitor(st *store.Store, interval time.Duration, log *slog.Logger) *HealthMonitor {
	return &HealthMonitor{
		store:    st,
		interval: interval,
		ttl:      3 * interval,
		log:      log.With("component", "health"),
		now:      time.Now,
		health:   make(map[string]nodeHealth),
	}
}

// Start launches the poll loop until ctx is cancelled, polling once immediately
// so liveness is known within one cycle of boot rather than after a full interval.
func (m *HealthMonitor) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		m.poll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.poll(ctx)
			}
		}
	}()
}

// poll polls every registered node's capabilities, refreshing its record on
// success and pruning records for nodes no longer in the registry.
func (m *HealthMonitor) poll(ctx context.Context) {
	nodes, err := m.store.ListScannerNodes(ctx)
	if err != nil {
		m.log.Warn("list nodes for health poll", "err", err)
		return
	}
	live := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		live[n.ID] = true
		pctx, cancel := context.WithTimeout(ctx, pollTimeout)
		caps, err := NewScannerClient(n.Endpoint, n.Token).Capabilities(pctx)
		cancel()

		m.mu.Lock()
		rec := m.health[n.ID] // zero value if first poll
		if err == nil {
			rec.LastSeen = m.now()
			rec.Caps = caps
			rec.LastErr = ""
		} else {
			rec.LastErr = err.Error()
		}
		m.health[n.ID] = rec // record exists after first attempt ⇒ "known"
		m.mu.Unlock()

		if err != nil {
			m.log.Warn("node health poll failed", "node", n.Name, "err", err)
		}
	}

	m.mu.Lock()
	for id := range m.health {
		if !live[id] {
			delete(m.health, id)
		}
	}
	m.mu.Unlock()
}

// Get returns a node's liveness and whether it has been polled yet (known). An
// unknown node (added since the last poll) is not treated as unhealthy by callers.
func (m *HealthMonitor) Get(nodeID string) (NodeHealth, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.health[nodeID]
	if !ok {
		return NodeHealth{}, false
	}
	return NodeHealth{
		Healthy:      m.healthyLocked(rec),
		LastSeen:     rec.LastSeen,
		Capabilities: rec.Caps,
		LastError:    rec.LastErr,
	}, true
}

func (m *HealthMonitor) healthyLocked(h nodeHealth) bool {
	return !h.LastSeen.IsZero() && m.now().Sub(h.LastSeen) <= m.ttl
}
