package backend

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
		var caps types.Capabilities
		client, err := clientForNode(n)
		if err == nil {
			caps, err = client.Capabilities(pctx)
		}
		cancel()

		m.mu.Lock()
		rec := m.health[n.ID] // zero value if first poll
		if err == nil {
			rec.LastSeen = m.now()
			rec.Caps = caps
			rec.LastErr = ""
		} else {
			rec.LastErr = sanitizeHealthError(err)
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

// sanitizeHealthError strips the upstream response body that statusErr
// includes (up to 2048 bytes) so a viewer-readable health_error never
// reflects bytes from the polled destination. Full detail remains in the
// structured log line emitted by poll. It operates structurally: if the
// error wraps an httpStatusError (produced by statusErr), only the HTTP
// status is kept; otherwise the generic error is truncated. This avoids
// brittle string parsing of the "capabilities: <status>: <body>" format.
func sanitizeHealthError(err error) string {
	if err == nil {
		return ""
	}
	var se *httpStatusError
	if errors.As(err, &se) {
		// The error is a wrapped httpStatusError (e.g. from
		// fmt.Errorf("capabilities: %w", statusErr(resp))). Reconstruct only
		// the prefix and status, dropping the body. The prefix is determined
		// from the outer error's string to preserve "capabilities: " vs other
		// ops, but the body stripping is structural.
		msg := err.Error()
		const capPrefix = "capabilities: "
		if strings.HasPrefix(msg, capPrefix) {
			return truncate512(capPrefix + se.Status)
		}
		// Fallback for any other httpStatusError wrapper (e.g. "status: ").
		// Keep only the status line.
		return truncate512(se.Status)
	}
	return truncate512(err.Error())
}

// truncate512 caps a string to 512 bytes on a UTF-8 rune boundary so the
// JSON-serialized health_error never splits a multi-byte rune.
func truncate512(s string) string {
	if len(s) <= 512 {
		return s
	}
	truncated := s[:512]
	// Back up only while the final rune is an invalid single byte. This
	// handles a split multi-byte sequence at the 512-byte boundary without
	// discarding the entire message if an earlier byte was already invalid
	// (which would cause ValidString to stay false all the way to "").
	for len(truncated) > 0 {
		r, size := utf8.DecodeLastRuneInString(truncated)
		if r != utf8.RuneError || size != 1 {
			break
		}
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}
