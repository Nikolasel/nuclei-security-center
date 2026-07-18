package backend

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// newTestMonitor builds a monitor with a controllable clock and no store (the
// poll loop isn't exercised here — we drive the record map directly to test the
// TTL/known semantics that Get and clientForScan rely on).
func newTestMonitor(interval time.Duration, now *time.Time) *HealthMonitor {
	m := NewHealthMonitor(nil, interval, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	m.now = func() time.Time { return *now }
	return m
}

func TestHealthMonitorGet(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := now
	m := newTestMonitor(30*time.Second, &clock) // ttl = 90s

	// Unknown node: not polled yet.
	if _, known := m.Get("x"); known {
		t.Fatal("unpolled node should be unknown")
	}

	// A fresh successful poll → healthy, with caps.
	m.health["x"] = nodeHealth{LastSeen: clock, Caps: types.Capabilities{NucleiVersion: "v3.11.0"}}
	h, known := m.Get("x")
	if !known || !h.Healthy {
		t.Fatalf("want known+healthy, got known=%v healthy=%v", known, h.Healthy)
	}
	if h.Capabilities.NucleiVersion != "v3.11.0" {
		t.Errorf("nuclei version = %q, want v3.11.0", h.Capabilities.NucleiVersion)
	}

	// Within the TTL it stays healthy; past it, it ages out (still known).
	clock = now.Add(89 * time.Second)
	if h, _ := m.Get("x"); !h.Healthy {
		t.Error("node should still be healthy inside the TTL")
	}
	clock = now.Add(91 * time.Second)
	h, known = m.Get("x")
	if !known {
		t.Error("an aged-out node is still known (was polled)")
	}
	if h.Healthy {
		t.Error("node should be unhealthy past the TTL")
	}
}

func TestHealthMonitorNeverSucceeded(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := now
	m := newTestMonitor(30*time.Second, &clock)

	// A node polled but never reachable: record exists (known) with zero LastSeen.
	m.health["down"] = nodeHealth{}
	h, known := m.Get("down")
	if !known {
		t.Fatal("a polled-but-failed node is known")
	}
	if h.Healthy {
		t.Error("a node that never responded is unhealthy")
	}
}
