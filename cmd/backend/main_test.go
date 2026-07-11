package main

import (
	"context"
	"testing"
)

// TestBuildAuthenticatorFailsClosed verifies auth is fail-closed: an unset
// OIDC_ISSUER is a startup error unless AUTH_DISABLED=true is explicitly set.
func TestBuildAuthenticatorFailsClosed(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "")

	// No explicit opt-out -> must refuse to boot (returns an error).
	t.Setenv("AUTH_DISABLED", "")
	if _, err := buildAuthenticator(context.Background(), nil, nil); err == nil {
		t.Error("expected error when OIDC_ISSUER unset and AUTH_DISABLED not set")
	}

	// Any value other than the literal "true" is not a valid opt-out.
	t.Setenv("AUTH_DISABLED", "1")
	if _, err := buildAuthenticator(context.Background(), nil, nil); err == nil {
		t.Error("expected error when AUTH_DISABLED is a non-\"true\" value")
	}

	// Explicit opt-in to dev mode -> (nil, nil), no error.
	t.Setenv("AUTH_DISABLED", "true")
	auth, err := buildAuthenticator(context.Background(), nil, nil)
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
