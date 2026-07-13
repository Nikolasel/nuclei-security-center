package backend

import (
	"context"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// FindingsSearcher is the read/search seam for the deduplicated lifecycle
// findings list (#21). Postgres stays the system of record; a derived search
// index (OpenSearch) can drop in behind this interface with no change to
// handlers, for when findings search/volume outgrows Postgres. The default
// implementation reads straight from Postgres.
type FindingsSearcher interface {
	ListLifecycle(ctx context.Context, f store.LifecycleFilter) ([]store.LifecycleRow, int, error)
}

// pgSearcher is the default FindingsSearcher: it reads from Postgres directly,
// so search behaves identically whether or not a derived index is configured.
type pgSearcher struct{ store *store.Store }

func (p pgSearcher) ListLifecycle(ctx context.Context, f store.LifecycleFilter) ([]store.LifecycleRow, int, error) {
	return p.store.ListLifecycleFindings(ctx, f)
}
