package backend

import (
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestOverlayScanPolicy(t *testing.T) {
	base := types.ScanOptions{RateLimit: 150, Concurrency: 25, TimeoutSec: 600}

	// A policy that sets only max_host_error overrides that knob and leaves the
	// rest of the base untouched — the "tune one thing" case the feature exists
	// for (raise max-host-error for a fragile device).
	got := overlayScanPolicy(base, store.ScanPolicy{MaxHostError: ptr(100)})
	want := types.ScanOptions{RateLimit: 150, Concurrency: 25, TimeoutSec: 600, MaxHostError: 100}
	if got != want {
		t.Errorf("partial overlay = %+v, want %+v", got, want)
	}

	// A fully-specified policy replaces every knob.
	full := overlayScanPolicy(base, store.ScanPolicy{
		RateLimit: ptr(20), Concurrency: ptr(5), TimeoutSec: ptr(1200), MaxHostError: ptr(50),
	})
	if full != (types.ScanOptions{RateLimit: 20, Concurrency: 5, TimeoutSec: 1200, MaxHostError: 50}) {
		t.Errorf("full overlay = %+v", full)
	}

	// An all-nil policy is a no-op (leaves the base exactly).
	if noop := overlayScanPolicy(base, store.ScanPolicy{Name: "empty"}); noop != base {
		t.Errorf("empty-policy overlay mutated base: %+v", noop)
	}
}
