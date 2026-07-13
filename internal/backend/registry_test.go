package backend

import (
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestRegistryHealthyExpiry(t *testing.T) {
	r := NewRegistry(60 * time.Second)
	now := time.Now()
	r.now = func() time.Time { return now }

	r.Register(types.NodeRegistration{Name: "n1", Endpoint: "http://n1:8081"})
	if _, ok := r.Pick(""); !ok {
		t.Fatal("fresh node should be pickable")
	}

	// Advance past the TTL: the node is now stale and unpickable.
	now = now.Add(2 * time.Minute)
	if _, ok := r.Pick(""); ok {
		t.Fatal("stale node should not be pickable")
	}
	// It still appears in List, marked unhealthy.
	list := r.List()
	if len(list) != 1 || list[0].Healthy {
		t.Fatalf("expected 1 unhealthy node, got %+v", list)
	}
}

func TestRegistryZoneFilter(t *testing.T) {
	r := NewRegistry(time.Minute)
	r.Register(types.NodeRegistration{Name: "corp", Endpoint: "http://corp:8081", Zone: "corp"})
	r.Register(types.NodeRegistration{Name: "dmz", Endpoint: "http://dmz:8081", Zone: "dmz"})
	r.Register(types.NodeRegistration{Name: "any", Endpoint: "http://any:8081"}) // no zone → catch-all

	// A corp scan may land on the corp node or the zoneless catch-all, never dmz.
	for i := 0; i < 10; i++ {
		n, ok := r.Pick("corp")
		if !ok {
			t.Fatal("expected a node for corp")
		}
		if n.Zone == "dmz" {
			t.Fatalf("corp scan routed to dmz node: %+v", n)
		}
	}
}

func TestRegistryRoundRobin(t *testing.T) {
	r := NewRegistry(time.Minute)
	r.Register(types.NodeRegistration{Name: "a", Endpoint: "http://a:8081"})
	r.Register(types.NodeRegistration{Name: "b", Endpoint: "http://b:8081"})

	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		n, ok := r.Pick("")
		if !ok {
			t.Fatal("expected a node")
		}
		seen[n.Endpoint]++
	}
	// Both nodes should get roughly half the traffic (stable sort + counter).
	if seen["http://a:8081"] != 5 || seen["http://b:8081"] != 5 {
		t.Fatalf("round-robin uneven: %v", seen)
	}
}

func TestRegistryReRegisterRefreshes(t *testing.T) {
	r := NewRegistry(60 * time.Second)
	now := time.Now()
	r.now = func() time.Time { return now }
	r.Register(types.NodeRegistration{Name: "n1", Endpoint: "http://n1:8081", Zone: "z1"})

	now = now.Add(30 * time.Second)
	// Re-register (heartbeat) with an updated zone; endpoint is the identity.
	r.Register(types.NodeRegistration{Name: "n1", Endpoint: "http://n1:8081", Zone: "z2"})

	now = now.Add(45 * time.Second) // 45s since the heartbeat, within TTL
	n, ok := r.Pick("")
	if !ok {
		t.Fatal("re-registered node should still be healthy")
	}
	if n.Zone != "z2" {
		t.Fatalf("zone = %q, want the refreshed z2", n.Zone)
	}
	if len(r.List()) != 1 {
		t.Fatalf("re-register should upsert, not duplicate: %+v", r.List())
	}
}
