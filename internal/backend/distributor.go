package backend

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TemplateDistributor pushes the full template catalog to each scanner node so a
// scan can later select templates by id from a tree the node already holds (#85).
// It runs periodically, only pushing to a node that is BOTH stale (its reported
// bundle digest != the current catalog digest) and idle (no running scan, so the
// tree is never swapped under a live nuclei). Strictly backend→node.
type TemplateDistributor struct {
	store    *store.Store
	health   *HealthMonitor
	interval time.Duration
	log      *slog.Logger
}

func NewTemplateDistributor(st *store.Store, health *HealthMonitor, interval time.Duration, log *slog.Logger) *TemplateDistributor {
	return &TemplateDistributor{store: st, health: health, interval: interval, log: log.With("component", "template_distributor")}
}

// Start runs a distribution pass immediately, then on the configured cadence.
func (d *TemplateDistributor) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()
		d.distribute(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.distribute(ctx)
			}
		}
	}()
}

// distribute pushes the current catalog to every stale, idle node. The full
// bundle is built at most once per pass, and only if some node actually needs it.
func (d *TemplateDistributor) distribute(ctx context.Context) {
	entries, err := d.store.ActiveTemplateBundleEntries(ctx)
	if err != nil {
		d.log.Error("read catalog entries", "err", err)
		return
	}
	if len(entries) == 0 {
		return // nothing synced into the catalog yet (e.g. sync disabled); no-op
	}
	catalogDigest := types.BundleDigest(entries)

	nodes, err := d.store.ListScannerNodes(ctx)
	if err != nil {
		d.log.Error("list nodes", "err", err)
		return
	}
	var bundle []byte // built lazily on the first node that needs it
	for _, n := range nodes {
		if !d.nodeNeedsCatalog(n.ID, catalogDigest) {
			continue
		}
		busy, err := d.store.NodeHasActiveScan(ctx, n.ID)
		if err != nil {
			d.log.Error("check node busy", "node", n.ID, "err", err)
			continue
		}
		if busy {
			d.log.Info("skip catalog push: node has a running scan", "node", n.ID)
			continue
		}
		if bundle == nil {
			if bundle, err = d.buildBundle(ctx); err != nil {
				d.log.Error("build catalog bundle", "err", err)
				return
			}
		}
		d.pushTo(ctx, n, bundle, catalogDigest)
	}
}

// nodeNeedsCatalog reports whether the node's last reported bundle digest differs
// from the current catalog digest. Using the node's REPORTED digest (from the
// health poll) makes this self-healing: a wiped/restarted node reports an empty
// or old digest and gets re-synced, independent of what the DB thinks it pushed.
func (d *TemplateDistributor) nodeNeedsCatalog(nodeID, catalogDigest string) bool {
	if h, ok := d.health.Get(nodeID); ok {
		return h.Capabilities.TemplatesCommit != catalogDigest
	}
	return true // never polled ⇒ assume stale
}

func (d *TemplateDistributor) buildBundle(ctx context.Context) ([]byte, error) {
	bodies, err := d.store.ListActiveTemplateBodies(ctx)
	if err != nil {
		return nil, err
	}
	bundle, _, err := buildCatalogBundle(bodies)
	return bundle, err
}

func (d *TemplateDistributor) pushTo(ctx context.Context, n store.ScannerNode, bundle []byte, catalogDigest string) {
	client, err := clientForNode(n)
	if err != nil {
		d.log.Error("build node client", "node", n.ID, "err", err)
		return
	}
	status, err := client.PushBundle(ctx, bundle)
	if err != nil {
		d.log.Error("push catalog bundle", "node", n.ID, "err", err)
		return
	}
	if err := d.store.SetNodeTemplatesSyncedAt(ctx, n.ID, time.Now().UTC()); err != nil {
		d.log.Error("record node sync time", "node", n.ID, "err", err)
	}
	d.log.Info("catalog pushed to node", "node", n.ID, "templates_commit", status.TemplatesCommit, "count", status.TemplateCount)
}

// SyncNode builds the current catalog bundle and pushes it to one node on demand
// (the admin "sync now" action). Unlike the periodic pass it does not skip on the
// staleness check — an admin forcing a sync wants the push to happen — but the
// node still verifies + activates, and (in the cutover slice) refuses while busy.
func (d *TemplateDistributor) SyncNode(ctx context.Context, nodeID string) (types.TemplateBundleStatus, error) {
	n, err := d.store.GetScannerNode(ctx, nodeID)
	if err != nil {
		return types.TemplateBundleStatus{}, err
	}
	bundle, err := d.buildBundle(ctx)
	if err != nil {
		return types.TemplateBundleStatus{}, fmt.Errorf("build catalog bundle: %w", err)
	}
	client, err := clientForNode(n)
	if err != nil {
		return types.TemplateBundleStatus{}, err
	}
	status, err := client.PushBundle(ctx, bundle)
	if err != nil {
		return types.TemplateBundleStatus{}, err
	}
	if err := d.store.SetNodeTemplatesSyncedAt(ctx, nodeID, time.Now().UTC()); err != nil {
		d.log.Error("record node sync time", "node", nodeID, "err", err)
	}
	return status, nil
}
