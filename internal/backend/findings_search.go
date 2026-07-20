package backend

import (
	"context"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// FindingsSearcher is the read/search seam for the deduplicated lifecycle
// findings list (GET /api/findings). The default implementation reads straight
// from Postgres, which is the system of record. A derived search index can be
// added later behind this interface with no change to handlers.
type FindingsSearcher interface {
	ListLifecycle(ctx context.Context, q store.FindingQuery, limit, offset int) ([]store.LifecycleRow, int, error)
}

// pgSearcher is the default FindingsSearcher: it reads from Postgres directly.
type pgSearcher struct{ store *store.Store }

func (p pgSearcher) ListLifecycle(ctx context.Context, q store.FindingQuery, limit, offset int) ([]store.LifecycleRow, int, error) {
	return p.store.ListLifecycleFindings(ctx, q, limit, offset)
}
