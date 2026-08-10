package backend

import (
	"errors"
	"sync"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// ErrScanCapacity means the backend cannot admit another scan for the selected
// node without exceeding that node's configured resource budget.
var ErrScanCapacity = errors.New("scan admission capacity exhausted")

// scanAdmission tracks backend polling/dispatch goroutines per scanner node.
// The node registry owns each limit, so heterogeneous scanner zones can have
// independent capacities while the backend remains bounded at every node.
type scanAdmission struct {
	mu     sync.Mutex
	active map[string]int
}

func newScanAdmission() *scanAdmission {
	return &scanAdmission{active: make(map[string]int)}
}

func (a *scanAdmission) acquire(nodeID string, limit int) error {
	if limit <= 0 {
		limit = types.DefaultMaxConcurrentScans
	}
	if nodeID == "" || limit > types.MaxConcurrentScansCeiling {
		return errors.New("invalid scanner node admission configuration")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active[nodeID] >= limit {
		return ErrScanCapacity
	}
	a.active[nodeID]++
	return nil
}

func (a *scanAdmission) release(nodeID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active[nodeID] <= 1 {
		delete(a.active, nodeID)
		return
	}
	a.active[nodeID]--
}
