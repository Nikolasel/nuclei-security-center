package backend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSameOriginRequest(t *testing.T) {
	tests := []struct {
		name       string
		origin     string
		fetchSite  string
		configured string
		want       bool
	}{
		{name: "matching origin", origin: "https://nsc.example.com", configured: "https://nsc.example.com", want: true},
		{name: "matching origin with default port", origin: "https://nsc.example.com:443", configured: "https://nsc.example.com", want: true},
		{name: "matching origin with root slash", origin: "https://nsc.example.com/", configured: "https://nsc.example.com/app", want: true},
		{name: "foreign origin", origin: "https://evil.example", configured: "https://nsc.example.com", want: false},
		{name: "same site is not same origin", origin: "https://uploads.example.com", fetchSite: "same-site", configured: "https://nsc.example.com", want: false},
		{name: "fetch metadata fallback", fetchSite: "same-origin", configured: "https://nsc.example.com", want: true},
		{name: "missing browser signals", configured: "https://nsc.example.com", want: false},
		{name: "origin and contradictory fetch metadata", origin: "https://nsc.example.com", fetchSite: "cross-site", configured: "https://nsc.example.com", want: false},
		{name: "null origin", origin: "null", configured: "https://nsc.example.com", want: false},
		{name: "path is not an origin", origin: "https://nsc.example.com/attacker", configured: "https://nsc.example.com", want: false},
		{name: "missing configuration fails closed", origin: "https://nsc.example.com", configured: "", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/targets", nil)
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			if test.fetchSite != "" {
				r.Header.Set("Sec-Fetch-Site", test.fetchSite)
			}
			if got := sameOriginRequest(r, test.configured); got != test.want {
				t.Fatalf("sameOriginRequest() = %v, want %v", got, test.want)
			}
		})
	}

	duplicate := httptest.NewRequest(http.MethodPost, "/api/targets", nil)
	duplicate.Header.Add("Origin", "https://nsc.example.com")
	duplicate.Header.Add("Origin", "https://nsc.example.com")
	if sameOriginRequest(duplicate, "https://nsc.example.com") {
		t.Fatal("multiple Origin headers should fail closed")
	}
}

func TestMutationOriginAllowedCredentialModes(t *testing.T) {
	s := &Server{auth: &Authenticator{cfg: AuthConfig{PublicOrigin: "https://nsc.example.com"}}}

	foreign := httptest.NewRequest(http.MethodPost, "/api/targets", nil)
	foreign.Header.Set("Origin", "https://evil.example")
	if s.mutationOriginAllowed(foreign) {
		t.Fatal("foreign cookie-authenticated origin should be rejected")
	}

	bearer := httptest.NewRequest(http.MethodPost, "/api/targets", nil)
	bearer.Header.Set("Authorization", "Bearer nsc_test")
	bearer.Header.Set("Origin", "https://evil.example")
	if !s.mutationOriginAllowed(bearer) {
		t.Fatal("explicit bearer callers should not require browser origin headers")
	}

	dev := &Server{}
	if !dev.mutationOriginAllowed(foreign) {
		t.Fatal("auth-disabled development should not require browser origin headers")
	}
}

func TestSameOriginRejectsForeignPost(t *testing.T) {
	s := &Server{auth: &Authenticator{cfg: AuthConfig{PublicOrigin: "https://nsc.example.com"}}}
	called := false
	h := s.sameOrigin(func(http.ResponseWriter, *http.Request) {
		called = true
	})

	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/targets", nil)
	r.Header.Set("Origin", "https://evil.example")
	h(rr, r)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if called {
		t.Fatal("foreign-origin handler was called")
	}
}

func TestDecodeJSONRequiresApplicationJSON(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{name: "missing", want: false},
		{name: "form", contentType: "application/x-www-form-urlencoded", want: false},
		{name: "plain text", contentType: "text/plain", want: false},
		{name: "json", contentType: "application/json", want: true},
		{name: "json with charset", contentType: "application/json; charset=utf-8", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/targets", strings.NewReader(`{"name":"target"}`))
			if test.contentType != "" {
				r.Header.Set("Content-Type", test.contentType)
			}
			var got map[string]string
			rr := httptest.NewRecorder()
			if decoded := decodeJSON(rr, r, &got); decoded != test.want {
				t.Fatalf("decodeJSON() = %v, want %v", decoded, test.want)
			}
			if test.want && got["name"] != "target" {
				t.Fatalf("decoded body = %v", got)
			}
			if !test.want && rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestJSONMutationRoutesRequireApplicationJSON(t *testing.T) {
	h := (&Server{spa: http.NotFoundHandler()}).Handler()
	routes := []struct {
		name string
		path string
		body string
	}{
		{name: "scan create", path: "/api/scans", body: `{"scan_policy_id":"p1","target_id":"t1"}`},
		{name: "finding disposition", path: "/api/findings/1/disposition", body: `{"disposition":"accepted"}`},
		{name: "finding severity", path: "/api/findings/1/severity", body: `{"severity":"high"}`},
		{name: "settings", path: "/api/settings", body: `{"retention_enabled":false}`},
	}

	for _, route := range routes {
		for _, contentType := range []string{"", "text/plain"} {
			name := route.name + "/"
			if contentType == "" {
				name += "missing-content-type"
			} else {
				name += "text-plain"
			}
			t.Run(name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(route.body))
				if route.path == "/api/findings/1/disposition" || route.path == "/api/findings/1/severity" {
					r.Method = http.MethodPatch
				} else if route.path == "/api/settings" {
					r.Method = http.MethodPut
				}
				if contentType != "" {
					r.Header.Set("Content-Type", contentType)
				}

				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, r)
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusBadRequest, rr.Body.String())
				}
			})
		}
	}
}
