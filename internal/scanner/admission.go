package scanner

import (
	"errors"
	"sync"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// DefaultMaxConcurrentScans is the node-side fallback used when a direct node
// caller does not provide the backend registry's per-node limit.
const DefaultMaxConcurrentScans = types.DefaultMaxConcurrentScans

// MaxConcurrentScansCeiling mirrors the shared wire-contract ceiling for the
// node's fallback environment setting and direct callers.
const MaxConcurrentScansCeiling = types.MaxConcurrentScansCeiling

// ErrScanCapacity means the node refuses a scan because admitting it would
// exceed the configured process/resource budget.
var ErrScanCapacity = errors.New("scanner scan capacity exhausted")

// ErrInvalidScanCapacity means a caller supplied a limit outside the shared
// safety range. Backend-dispatched scans are validated by the admin API first;
// the node repeats the check at its trust boundary.
var ErrInvalidScanCapacity = errors.New("invalid scanner scan capacity")

type scanAdmission struct {
	mu       sync.Mutex
	fallback int
	limit    int
	active   int
}

func newScanAdmission(limit int) *scanAdmission {
	if limit < 1 || limit > MaxConcurrentScansCeiling {
		limit = DefaultMaxConcurrentScans
	}
	return &scanAdmission{fallback: limit, limit: limit}
}

// acquire applies requestedLimit when non-zero, or restores the node-local
// fallback for a legacy/direct request that omits it, then admits one scan
// without waiting. The backend sends the registered node's limit on every
// dispatch, so an admin edit takes effect on the next scan without restarting
// the node.
func (a *scanAdmission) acquire(requestedLimit int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if requestedLimit < 0 || requestedLimit > types.MaxConcurrentScansCeiling {
		return ErrInvalidScanCapacity
	}
	limit := a.fallback
	if requestedLimit > 0 {
		limit = requestedLimit
	}
	a.limit = limit
	if a.active >= a.limit {
		return ErrScanCapacity
	}
	a.active++
	return nil
}

func (a *scanAdmission) release() {
	a.mu.Lock()
	a.active--
	a.mu.Unlock()
}
