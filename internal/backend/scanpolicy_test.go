package backend

import (
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestOverlayScanPolicy(t *testing.T) {
	base := types.ScanOptions{RateLimit: 150, Concurrency: 25, TimeoutSec: 600}

	// knobsOf strips the Discovery pointer so the execution knobs can be compared
	// by value (Discovery is asserted separately in each case).
	knobsOf := func(o types.ScanOptions) types.ScanOptions { o.Discovery = nil; return o }

	// A policy that sets only max_host_error overrides that knob and leaves the
	// rest of the base untouched — the "tune one thing" case the feature exists
	// for (raise max-host-error for a fragile device).
	got := overlayScanPolicy(base, store.ScanPolicy{MaxHostError: ptr(100)})
	want := types.ScanOptions{RateLimit: 150, Concurrency: 25, TimeoutSec: 600, MaxHostError: 100}
	if knobsOf(got) != want {
		t.Errorf("partial overlay = %+v, want %+v", knobsOf(got), want)
	}
	// A policy with no discovery fields set still defaults discovery ON (#86).
	if got.Discovery == nil || !got.Discovery.Enabled {
		t.Errorf("discovery should default ON when unset, got %+v", got.Discovery)
	}

	// A fully-specified policy replaces every knob and carries discovery config.
	full := overlayScanPolicy(base, store.ScanPolicy{
		RateLimit: ptr(20), Concurrency: ptr(5), TimeoutSec: ptr(1200), MaxHostError: ptr(50),
		DiscoveryEnabled: ptr(true), DiscoveryScanType: "connect", DiscoveryPorts: "80,443,8000-9000",
		DiscoveryTimeoutSec: ptr(120),
	})
	if knobsOf(full) != (types.ScanOptions{RateLimit: 20, Concurrency: 5, TimeoutSec: 1200, MaxHostError: 50}) {
		t.Errorf("full overlay = %+v", knobsOf(full))
	}
	if full.Discovery == nil || !full.Discovery.Enabled || full.Discovery.ScanType != "connect" ||
		full.Discovery.Ports != "80,443,8000-9000" || full.Discovery.TimeoutSec != 120 {
		t.Errorf("discovery overlay = %+v", full.Discovery)
	}

	// An all-nil policy leaves the knobs untouched but still turns discovery ON.
	noop := overlayScanPolicy(base, store.ScanPolicy{Name: "empty"})
	if knobsOf(noop) != base {
		t.Errorf("empty-policy overlay mutated knobs: %+v", knobsOf(noop))
	}
	if noop.Discovery == nil || !noop.Discovery.Enabled {
		t.Errorf("empty-policy discovery should default ON, got %+v", noop.Discovery)
	}

	// An explicit opt-out disables discovery.
	off := overlayScanPolicy(base, store.ScanPolicy{DiscoveryEnabled: ptr(false)})
	if off.Discovery == nil || off.Discovery.Enabled {
		t.Errorf("explicit opt-out should disable discovery, got %+v", off.Discovery)
	}
}
