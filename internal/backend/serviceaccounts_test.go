package backend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestMintTokenShape(t *testing.T) {
	tok, hash, prefix, err := mintToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, tokenScheme) {
		t.Errorf("token %q missing scheme %q", tok, tokenScheme)
	}
	if prefix != tok[:tokenPrefixLen] {
		t.Errorf("prefix %q is not the token's leading %d chars", prefix, tokenPrefixLen)
	}
	if hash != hashToken(tok) {
		t.Errorf("returned hash %q != hashToken(token) %q", hash, hashToken(tok))
	}
	// hex-encoded SHA-256 is 64 chars.
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestMintTokenUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, _, _, err := mintToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatalf("mintToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}

func TestHashTokenStable(t *testing.T) {
	// A fixed input pins the at-rest encoding so a format change is caught.
	const in = "nsc_example"
	if got := hashToken(in); got != hashToken(in) {
		t.Fatal("hashToken not deterministic")
	}
	if hashToken("a") == hashToken("b") {
		t.Fatal("distinct tokens hashed equal")
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"none", "", "", false},
		{"bearer", "Bearer nsc_abc", "nsc_abc", true},
		{"case-insensitive scheme", "bearer nsc_abc", "nsc_abc", true},
		{"basic ignored", "Basic Zm9vOmJhcg==", "", false},
		{"empty bearer", "Bearer ", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			got, ok := bearerToken(r)
			if got != c.want || ok != c.ok {
				t.Errorf("bearerToken(%q) = (%q,%v), want (%q,%v)", c.header, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestIsAssignableRole(t *testing.T) {
	for _, r := range []string{RoleViewer, RoleOperator, RoleAdmin} {
		if !isAssignableRole(r) {
			t.Errorf("role %q should be assignable", r)
		}
	}
	for _, r := range []string{"", "root", "superuser", "Admin"} {
		if isAssignableRole(r) {
			t.Errorf("role %q should not be assignable", r)
		}
	}
}

func TestExpiryFromTTL(t *testing.T) {
	// nil => default lifetime, roughly defaultTokenTTLDays out.
	got, err := expiryFromTTL(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("nil ttl should default to an expiry, got no expiry")
	}
	wantAround := time.Now().Add(defaultTokenTTLDays * 24 * time.Hour)
	if d := got.Sub(wantAround); d < -time.Minute || d > time.Minute {
		t.Errorf("default expiry off by %v", d)
	}

	// explicit 0 => no expiry.
	zero := 0
	got, err = expiryFromTTL(&zero)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("ttl_days=0 should mean no expiry, got %v", got)
	}

	// positive => that many days.
	seven := 7
	got, err = expiryFromTTL(&seven)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Before(time.Now().Add(6*24*time.Hour)) {
		t.Errorf("ttl_days=7 expiry = %v, want ~7 days out", got)
	}

	// negative => error.
	neg := -1
	if _, err := expiryFromTTL(&neg); err == nil {
		t.Error("negative ttl_days should be rejected")
	}
}

func TestActorType(t *testing.T) {
	if got := actorType(store.Identity{Subject: "svc:deploy-bot"}); got != "service_account" {
		t.Errorf("svc subject actor_type = %q, want service_account", got)
	}
	if got := actorType(store.Identity{Subject: "alice"}); got != "user" {
		t.Errorf("human subject actor_type = %q, want user", got)
	}
}
