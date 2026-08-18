package backend

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestLoginAdmissionAllowsBurstThenRejectsUntilRefill(t *testing.T) {
	now := time.Unix(100, 0)
	admission := newLoginAdmission()
	admission.now = func() time.Time { return now }

	for i := 0; i < authLoginBurst; i++ {
		if !admission.allow("192.0.2.1") {
			t.Fatalf("request %d in configured burst was rejected", i+1)
		}
	}
	if admission.allow("192.0.2.1") {
		t.Fatal("request beyond the configured burst was accepted")
	}

	now = now.Add(time.Second)
	if !admission.allow("192.0.2.1") {
		t.Fatal("request after one refill interval was rejected")
	}
}

func TestLoginAdmissionReadsClockUnderMutex(t *testing.T) {
	admission := newLoginAdmission()
	admission.now = func() time.Time {
		if admission.mu.TryLock() {
			admission.mu.Unlock()
			t.Error("login admission read the clock before taking its mutex")
		}
		return time.Unix(100, 0)
	}

	if !admission.allow("192.0.2.1") {
		t.Fatal("first login admission was rejected")
	}
}

func TestLoginAdmissionEvictsStalestClientAtBound(t *testing.T) {
	now := time.Unix(100, 0)
	admission := newLoginAdmission()
	admission.maxClients = 1
	admission.now = func() time.Time { return now }

	if !admission.allow("192.0.2.1") {
		t.Fatal("first client was rejected")
	}
	now = now.Add(time.Second)
	if !admission.allow("192.0.2.2") {
		t.Fatal("new client was rejected after the client-state bound was reached")
	}
	if got := len(admission.clients); got != 1 {
		t.Fatalf("tracked client count = %d, want 1", got)
	}
	if _, ok := admission.clients["192.0.2.1"]; ok {
		t.Fatal("stale client was not evicted")
	}
	if _, ok := admission.clients["192.0.2.2"]; !ok {
		t.Fatal("new client was not tracked")
	}

	now = now.Add(time.Second)
	if !admission.allow("192.0.2.3") {
		t.Fatal("new client was rejected after stale-state eviction")
	}
	if got := len(admission.clients); got != 1 {
		t.Fatalf("tracked client count after eviction = %d, want 1", got)
	}
}

func TestLoginAdmissionEvictsLeastRecentlySeenClient(t *testing.T) {
	now := time.Unix(100, 0)
	admission := newLoginAdmission()
	admission.maxClients = 2
	admission.now = func() time.Time { return now }

	if !admission.allow("192.0.2.1") {
		t.Fatal("first client was rejected")
	}
	now = now.Add(time.Second)
	if !admission.allow("192.0.2.2") {
		t.Fatal("second client was rejected")
	}
	now = now.Add(time.Second)
	if !admission.allow("192.0.2.1") {
		t.Fatal("existing client was rejected")
	}
	now = now.Add(time.Second)
	if !admission.allow("192.0.2.3") {
		t.Fatal("new client was rejected")
	}
	if _, ok := admission.clients["192.0.2.2"]; ok {
		t.Fatal("least-recently-seen client was not evicted")
	}
	if _, ok := admission.clients["192.0.2.1"]; !ok {
		t.Fatal("more recently seen client was evicted")
	}
}

func TestAuthLoginClientKeyUsesPeerAddressNotForwardedHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	req.RemoteAddr = "192.0.2.7:43122"
	req.Header.Set("X-Forwarded-For", "198.51.100.9")

	if got := authLoginClientKey(req, nil); got != "192.0.2.7" {
		t.Fatalf("authLoginClientKey = %q, want peer address", got)
	}
}

func TestAuthLoginClientKeyUsesForwardedAddressOnlyFromTrustedPeer(t *testing.T) {
	trustedProxy := netip.MustParsePrefix("10.0.0.0/8")
	cases := []struct {
		name       string
		remoteAddr string
		forwarded  string
		trusted    trustedProxySet
		want       string
	}{
		{
			name:       "direct peer ignores forwarded header",
			remoteAddr: "192.0.2.7:43122",
			forwarded:  "198.51.100.9",
			want:       "192.0.2.7",
		},
		{
			name:       "trusted proxy uses client address",
			remoteAddr: "10.0.0.8:443",
			forwarded:  "198.51.100.9",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy}),
			want:       "198.51.100.9",
		},
		{
			name:       "trusted proxy walks multi-hop chain",
			remoteAddr: "10.0.0.8:443",
			forwarded:  "198.51.100.9, 10.0.0.7",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy}),
			want:       "198.51.100.9",
		},
		{
			name:       "untrusted peer ignores forwarded header",
			remoteAddr: "192.0.2.7:43122",
			forwarded:  "198.51.100.9",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy}),
			want:       "192.0.2.7",
		},
		{
			name:       "malformed right token preserves valid client",
			remoteAddr: "10.0.0.8:443",
			forwarded:  "198.51.100.9, not-an-ip",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy}),
			want:       "198.51.100.9",
		},
		{
			name:       "all trusted chain falls back to proxy",
			remoteAddr: "10.0.0.8:443",
			forwarded:  "10.0.0.9, 10.0.0.7",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy}),
			want:       "10.0.0.8",
		},
		{
			name:       "IPv4-mapped trusted hop is normalized",
			remoteAddr: "10.0.0.8:443",
			forwarded:  "203.0.113.9, ::ffff:172.18.0.7",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy, netip.MustParsePrefix("172.18.0.0/16")}),
			want:       "203.0.113.9",
		},
		{
			name:       "IPv4-mapped direct peer is trusted",
			remoteAddr: "[::ffff:10.0.0.8]:443",
			forwarded:  "203.0.113.9",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy}),
			want:       "203.0.113.9",
		},
		{
			name:       "attacker junk to the left does not discard valid client",
			remoteAddr: "10.0.0.8:443",
			forwarded:  "junk, 198.51.100.9",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy}),
			want:       "198.51.100.9",
		},
		{
			name:       "large left padding does not discard right client",
			remoteAddr: "10.0.0.8:443",
			forwarded:  strings.Repeat("junk,", 1000) + "198.51.100.9",
			trusted:    newTrustedProxySet([]netip.Prefix{trustedProxy}),
			want:       "198.51.100.9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
			req.RemoteAddr = tc.remoteAddr
			req.Header.Set("X-Forwarded-For", tc.forwarded)
			if got := authLoginClientKey(req, tc.trusted); got != tc.want {
				t.Fatalf("authLoginClientKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewTrustedProxySetNormalizesPrefixes(t *testing.T) {
	got := newTrustedProxySet([]netip.Prefix{
		netip.MustParsePrefix("::ffff:172.18.0.0/112"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	if got[0].String() != "172.18.0.0/16" {
		t.Fatalf("mapped trusted prefix = %q, want 172.18.0.0/16", got[0])
	}
	if got[1].String() != "2001:db8::/32" {
		t.Fatalf("IPv6 trusted prefix = %q, want 2001:db8::/32", got[1])
	}
}

func TestHandleLoginRejectsAdmissionBeforeStoreAccess(t *testing.T) {
	a := &Authenticator{}
	admission := newLoginAdmission()
	admission.maxClients = 0
	a.loginAdmissionOnce.Do(func() {
		a.loginAdmission = admission
	})

	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	req.RemoteAddr = "192.0.2.8:43122"
	rr := httptest.NewRecorder()
	a.handleLogin(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited login status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
	if got := rr.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

func TestAuthReturnToDropsInvalidAndOversizedValues(t *testing.T) {
	if got := authReturnTo("/dashboard?tab=findings"); got != "/dashboard?tab=findings" {
		t.Fatalf("valid return_to = %q, want preserved value", got)
	}
	for _, value := range []string{"//attacker.example", strings.Repeat("a", maxAuthReturnToBytes+1)} {
		if got := authReturnTo(value); got != "" {
			t.Fatalf("authReturnTo(%q) = %q, want empty", value, got)
		}
	}
}

func TestLoginAdmissionUsesConfiguredValues(t *testing.T) {
	a := &Authenticator{cfg: AuthConfig{
		LoginRate:       2.5,
		LoginBurst:      12,
		LoginMaxClients: 9,
	}}
	admission := a.loginAdmitter()
	if admission.limit != 2.5 || admission.burst != 12 || admission.maxClients != 9 {
		t.Fatalf("configured login admission = %v/%d/%d, want 2.5/12/9", admission.limit, admission.burst, admission.maxClients)
	}
}

func TestValidateLoginAdmissionConfigRejectsUnsafeValues(t *testing.T) {
	for _, cfg := range []AuthConfig{
		{LoginRate: -1},
		{LoginRate: MaxConfiguredAuthLoginRate + 1},
		{LoginBurst: -1},
		{LoginBurst: MaxConfiguredAuthLoginBurst + 1},
		{LoginMaxClients: -1},
		{LoginMaxClients: MaxConfiguredAuthLoginClients + 1},
	} {
		if err := validateLoginAdmissionConfig(cfg); err == nil {
			t.Fatalf("validateLoginAdmissionConfig(%+v) = nil, want error", cfg)
		}
	}
}
