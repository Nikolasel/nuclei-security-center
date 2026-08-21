package main

import (
	"context"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/backend"
	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// TestBuildAuthenticatorFailsClosed verifies auth is fail-closed: an unset
// OIDC_ISSUER is a startup error unless AUTH_DISABLED=true is explicitly set.
func TestBuildAuthenticatorFailsClosed(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "")

	// No explicit opt-out -> must refuse to boot (returns an error).
	t.Setenv("AUTH_DISABLED", "")
	if _, err := buildAuthenticator(context.Background(), nil, nil, authLoginAdmissionSettings{}); err == nil {
		t.Error("expected error when OIDC_ISSUER unset and AUTH_DISABLED not set")
	}

	// Any value other than the literal "true" is not a valid opt-out.
	t.Setenv("AUTH_DISABLED", "1")
	if _, err := buildAuthenticator(context.Background(), nil, nil, authLoginAdmissionSettings{}); err == nil {
		t.Error("expected error when AUTH_DISABLED is a non-\"true\" value")
	}

	// Explicit opt-in to dev mode -> (nil, nil), no error.
	t.Setenv("AUTH_DISABLED", "true")
	auth, err := buildAuthenticator(context.Background(), nil, nil, authLoginAdmissionSettings{})
	if err != nil || auth != nil {
		t.Errorf("AUTH_DISABLED=true: got (%v, %v), want (nil, nil)", auth, err)
	}
}

// TestSecureCookieEnabled verifies the cookie Secure flag is secure-by-default,
// disabled only by an explicit COOKIE_SECURE=false.
func TestSecureCookieEnabled(t *testing.T) {
	cases := map[string]bool{
		"":      true,  // unset -> Secure
		"true":  true,  // explicit on
		"1":     true,  // no longer silently insecure
		"True":  true,  // no longer silently insecure
		"false": false, // the one explicit opt-out
	}
	for val, want := range cases {
		t.Setenv("COOKIE_SECURE", val)
		if got := secureCookieEnabled(); got != want {
			t.Errorf("COOKIE_SECURE=%q -> %v, want %v", val, got, want)
		}
	}
}

func TestAuthLoginAdmissionFromEnvDefaultsAndOverrides(t *testing.T) {
	for _, name := range []string{"AUTH_LOGIN_RATE", "AUTH_LOGIN_BURST", "AUTH_LOGIN_MAX_CLIENTS"} {
		t.Setenv(name, "")
	}
	rateLimit, burst, maxClients, err := authLoginAdmissionFromEnv()
	if err != nil {
		t.Fatalf("default auth login settings: %v", err)
	}
	if rateLimit != backend.DefaultAuthLoginRate || burst != backend.DefaultAuthLoginBurst || maxClients != backend.DefaultAuthLoginMaxClients {
		t.Fatalf("default auth login settings = %v/%d/%d, want %v/%d/%d", rateLimit, burst, maxClients, backend.DefaultAuthLoginRate, backend.DefaultAuthLoginBurst, backend.DefaultAuthLoginMaxClients)
	}

	t.Setenv("AUTH_LOGIN_RATE", "2.5")
	t.Setenv("AUTH_LOGIN_BURST", "12")
	t.Setenv("AUTH_LOGIN_MAX_CLIENTS", "9000")
	rateLimit, burst, maxClients, err = authLoginAdmissionFromEnv()
	if err != nil {
		t.Fatalf("overridden auth login settings: %v", err)
	}
	if rateLimit != 2.5 || burst != 12 || maxClients != 9000 {
		t.Fatalf("overridden auth login settings = %v/%d/%d, want 2.5/12/9000", rateLimit, burst, maxClients)
	}
}

func TestAuthLoginAdmissionFromEnvRejectsOutOfRangeValues(t *testing.T) {
	cases := []struct {
		name  string
		env   string
		value string
	}{
		{name: "rate zero", env: "AUTH_LOGIN_RATE", value: "0"},
		{name: "rate NaN", env: "AUTH_LOGIN_RATE", value: "NaN"},
		{name: "rate text", env: "AUTH_LOGIN_RATE", value: "not-a-number"},
		{name: "burst zero", env: "AUTH_LOGIN_BURST", value: "0"},
		{name: "clients zero", env: "AUTH_LOGIN_MAX_CLIENTS", value: "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"AUTH_LOGIN_RATE", "AUTH_LOGIN_BURST", "AUTH_LOGIN_MAX_CLIENTS"} {
				t.Setenv(name, "")
			}
			t.Setenv(tc.env, tc.value)
			if _, _, _, err := authLoginAdmissionFromEnv(); err == nil {
				t.Fatalf("%s=%q was accepted", tc.env, tc.value)
			}
		})
	}
}

func TestStoreOptionsFromEnv(t *testing.T) {
	t.Setenv("AUTH_MAX_LIVE_FLOWS", "")
	opts, err := storeOptionsFromEnv()
	if err != nil {
		t.Fatalf("default store options: %v", err)
	}
	if opts.MaxLiveAuthFlows != store.DefaultMaxLiveAuthFlows {
		t.Fatalf("default MaxLiveAuthFlows = %d, want %d", opts.MaxLiveAuthFlows, store.DefaultMaxLiveAuthFlows)
	}

	t.Setenv("AUTH_MAX_LIVE_FLOWS", "20000")
	opts, err = storeOptionsFromEnv()
	if err != nil {
		t.Fatalf("overridden store options: %v", err)
	}
	if opts.MaxLiveAuthFlows != 20000 {
		t.Fatalf("overridden MaxLiveAuthFlows = %d, want 20000", opts.MaxLiveAuthFlows)
	}
}

func TestTrustedProxyCIDRsFromEnv(t *testing.T) {
	t.Setenv("AUTH_TRUSTED_PROXY_CIDRS", "")
	got, err := trustedProxyCIDRsFromEnv()
	if err != nil {
		t.Fatalf("default trusted proxy CIDRs: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("default trusted proxy CIDRs = %v, want empty", got)
	}

	t.Setenv("AUTH_TRUSTED_PROXY_CIDRS", "10.0.0.8/32, 2001:db8::/32, 10.0.0.8/32")
	got, err = trustedProxyCIDRsFromEnv()
	if err != nil {
		t.Fatalf("configured trusted proxy CIDRs: %v", err)
	}
	if len(got) != 2 || got[0].String() != "10.0.0.8/32" || got[1].String() != "2001:db8::/32" {
		t.Fatalf("configured trusted proxy CIDRs = %v, want two deduplicated prefixes", got)
	}

	t.Setenv("AUTH_TRUSTED_PROXY_CIDRS", "not-a-cidr")
	if _, err := trustedProxyCIDRsFromEnv(); err == nil {
		t.Fatal("invalid trusted proxy CIDR was accepted")
	}
}

// TestBuildAuthenticatorRejectsOutOfRangeSessionTTL verifies SESSION_TTL is
// bounded to the documented 15m..24h window (#189). The 720h example from the
// finding would keep a revoked admin authorized for a month.
func TestBuildAuthenticatorRejectsOutOfRangeSessionTTL(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://example.com")
	t.Setenv("OIDC_CLIENT_ID", "test-client")
	t.Setenv("OIDC_CLIENT_SECRET", "test-secret")
	t.Setenv("AUTH_DISABLED", "")

	cases := []struct {
		name    string
		ttl     string
		wantErr bool
	}{
		{name: "default 12h ok", ttl: "12h", wantErr: false},
		{name: "min 15m ok", ttl: "15m", wantErr: false},
		{name: "max 24h ok", ttl: "24h", wantErr: false},
		{name: "too short 1m reject", ttl: "1m", wantErr: true},
		{name: "too long 720h reject", ttl: "720h", wantErr: true},
		{name: "just over max 25h reject", ttl: "25h", wantErr: true},
		{name: "invalid duration reject", ttl: "not-a-duration", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SESSION_TTL", tc.ttl)
			_, err := buildAuthenticator(context.Background(), nil, nil, authLoginAdmissionSettings{})
			if tc.wantErr && err == nil {
				t.Fatalf("SESSION_TTL=%q: expected error, got nil", tc.ttl)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "SESSION_TTL") {
				t.Fatalf("SESSION_TTL=%q: error %q does not mention SESSION_TTL", tc.ttl, err)
			}
			if !tc.wantErr && err != nil && strings.Contains(err.Error(), "SESSION_TTL") {
				t.Fatalf("SESSION_TTL=%q: unexpected TTL error: %v", tc.ttl, err)
			}
			// Non-TTL errors (e.g. oidc discovery) are acceptable for the ok cases
			// because we use a dummy issuer without a real IdP.
		})
	}
}
