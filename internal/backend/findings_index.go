package backend

import (
	"context"
	"log/slog"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Indexer keeps the derived search index in sync with Postgres (#21). Because
// the lifecycle's detection/effective state is computed relative to a target's
// latest scan, sync is per-target (a completed scan can flip several of that
// target's findings) and fully rebuildable via ReindexAll.
type Indexer interface {
	// ReindexTarget re-projects one target's lifecycle findings into the index.
	ReindexTarget(ctx context.Context, targetID string) error
	// ReindexAll rebuilds the whole index from Postgres (backfill).
	ReindexAll(ctx context.Context) error
}

// osIndexer projects Postgres lifecycle rows into an OpenSearch index.
type osIndexer struct {
	client *OpenSearchClient
	store  *store.Store
	log    *slog.Logger
}

// NewOpenSearchIndexer wires an indexer over the store and OpenSearch client.
func NewOpenSearchIndexer(client *OpenSearchClient, st *store.Store, log *slog.Logger) *osIndexer {
	return &osIndexer{client: client, store: st, log: log}
}

// reindexBatch is how many rows are paged from Postgres and bulk-indexed at once.
const reindexBatch = 500

func (x *osIndexer) ReindexTarget(ctx context.Context, targetID string) error {
	if targetID == "" {
		return nil // ad-hoc scan, no stored target to re-project
	}
	return x.reindex(ctx, store.LifecycleFilter{TargetID: targetID})
}

func (x *osIndexer) ReindexAll(ctx context.Context) error {
	return x.reindex(ctx, store.LifecycleFilter{})
}

// reindex pages the filter's lifecycle rows out of Postgres and bulk-indexes
// each page. The rows carry the freshly-computed effective state/severity, so
// the projection matches what a Postgres read would return at this moment.
func (x *osIndexer) reindex(ctx context.Context, f store.LifecycleFilter) error {
	f.Limit = reindexBatch
	for offset := 0; ; offset += reindexBatch {
		f.Offset = offset
		rows, _, err := x.store.ListLifecycleFindings(ctx, f)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		if err := x.client.BulkIndex(ctx, rows); err != nil {
			return err
		}
		if len(rows) < reindexBatch {
			return nil
		}
	}
}
