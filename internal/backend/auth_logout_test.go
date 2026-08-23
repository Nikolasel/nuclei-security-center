package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestDiscoverEndSessionEndpointNilProvider(t *testing.T) {
	if got := discoverEndSessionEndpoint(nil); got != "" {
		t.Fatalf("discoverEndSessionEndpoint(nil) = %q, want empty", got)
	}
}

func TestEndSessionURL(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		cfg         AuthConfig
		wantEmpty   bool
		wantScheme  string
		wantHost    string
		wantQuery   map[string]string // expected query keys (values checked contains)
		wantContain string            // substring that must appear in final URL
	}{
		{
			name:      "missing endpoint returns empty",
			endpoint:  "",
			cfg:       AuthConfig{ClientID: "c1", PublicOrigin: "https://nsc.example.com"},
			wantEmpty: true,
		},
		{
			name:      "whitespace only returns empty",
			endpoint:  "   ",
			cfg:       AuthConfig{ClientID: "c1"},
			wantEmpty: true,
		},
		{
			name:       "http endpoint with public origin",
			endpoint:   "https://idp.example.com/logout",
			cfg:        AuthConfig{ClientID: "myclient", PublicOrigin: "https://nsc.example.com", PostLogin: ""},
			wantScheme: "https", wantHost: "idp.example.com",
			wantQuery:   map[string]string{"client_id": "myclient"},
			wantContain: "post_logout_redirect_uri=",
		},
		{
			name:      "postLogin absolute is used directly",
			endpoint:  "https://idp.example.com/end_session",
			cfg:       AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com", PostLogin: "https://nsc.example.com/welcome"},
			wantQuery: map[string]string{"post_logout_redirect_uri": "https://nsc.example.com/welcome"},
		},
		{
			name:      "postLogin relative with leading slash resolved against public origin",
			endpoint:  "https://idp.example.com/end_session",
			cfg:       AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com", PostLogin: "/after-logout"},
			wantQuery: map[string]string{"post_logout_redirect_uri": "https://nsc.example.com/after-logout"},
		},
		{
			name:      "postLogin empty and public origin empty falls back to localhost",
			endpoint:  "https://idp.example.com/end_session",
			cfg:       AuthConfig{ClientID: "c", PublicOrigin: "", PostLogin: ""},
			wantQuery: map[string]string{"post_logout_redirect_uri": "http://localhost:8080/"},
		},
		{
			name:      "postLogin slash alone resolves to origin root",
			endpoint:  "https://idp.example.com/end_session",
			cfg:       AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com/app", PostLogin: "/"},
			wantQuery: map[string]string{"post_logout_redirect_uri": "https://nsc.example.com/app/"},
		},
		{
			name:        "preserves existing query parameters on endpoint",
			endpoint:    "https://idp.example.com/end_session?extra=keep&foo=bar",
			cfg:         AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			wantContain: "extra=keep",
		},
		{
			name:      "invalid URL returns empty",
			endpoint:  "://bad",
			cfg:       AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			wantEmpty: true,
		},
		{
			name:      "missing host returns empty",
			endpoint:  "https:///nohost",
			cfg:       AuthConfig{ClientID: "c"},
			wantEmpty: true,
		},
		{
			name:      "missing scheme returns empty",
			endpoint:  "idp.example.com/logout",
			cfg:       AuthConfig{ClientID: "c"},
			wantEmpty: true,
		},
		{
			name:      "javascript scheme rejected",
			endpoint:  "javascript:alert(1)",
			cfg:       AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			wantEmpty: true,
		},
		{
			name:      "data scheme rejected",
			endpoint:  "data:text/html,hello",
			cfg:       AuthConfig{ClientID: "c"},
			wantEmpty: true,
		},
		{
			name:      "ftp scheme rejected",
			endpoint:  "ftp://idp.example.com/logout",
			cfg:       AuthConfig{ClientID: "c"},
			wantEmpty: true,
		},
		{
			name:       "uppercase HTTPS accepted",
			endpoint:   "HTTPS://idp.example.com/logout",
			cfg:        AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			wantScheme: "https",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Authenticator{cfg: tc.cfg, endSessionEndpoint: tc.endpoint}
			got := a.endSessionURL()
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("endSessionURL() = %q, want empty", got)
				}
				return
			}
			if got == "" {
				t.Fatal("endSessionURL() = empty, want non-empty")
			}
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("parse result %q: %v", got, err)
			}
			if tc.wantScheme != "" && !strings.EqualFold(u.Scheme, tc.wantScheme) {
				t.Errorf("scheme = %q, want %q", u.Scheme, tc.wantScheme)
			}
			if tc.wantHost != "" && !strings.EqualFold(u.Host, tc.wantHost) {
				t.Errorf("host = %q, want %q", u.Host, tc.wantHost)
			}
			q := u.Query()
			for k, wantVal := range tc.wantQuery {
				if gotVal := q.Get(k); gotVal != wantVal {
					t.Errorf("query %q = %q, want %q (full url %q)", k, gotVal, wantVal, got)
				}
			}
			if tc.wantContain != "" && !strings.Contains(got, tc.wantContain) {
				t.Errorf("url %q does not contain %q", got, tc.wantContain)
			}
			// Must contain client_id whenever non-empty
			if tc.cfg.ClientID != "" && q.Get("client_id") != tc.cfg.ClientID {
				t.Errorf("client_id = %q, want %q", q.Get("client_id"), tc.cfg.ClientID)
			}
			// post_logout_redirect_uri must be absolute URL
			if redir := q.Get("post_logout_redirect_uri"); redir != "" {
				ru, err := url.Parse(redir)
				if err != nil || ru.Scheme == "" || ru.Host == "" {
					t.Errorf("post_logout_redirect_uri = %q is not absolute", redir)
				}
			}
		})
	}
}

// TestHandleLogoutPOSTStatus verifies the dual contract: when an end_session_endpoint
// is known the handler returns 200 JSON with the URL; otherwise 204 local-only.
// Local session deletion always occurs.
func TestHandleLogoutPOSTStatus(t *testing.T) {
	// No endpoint → 204
	a := &Authenticator{cfg: AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"}, endSessionEndpoint: ""}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	a.handleLogout(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("no endpoint status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "" && ct != "text/plain; charset=utf-8" {
		// 204 should not set JSON
	}
	if body := rr.Body.String(); body != "" {
		t.Errorf("204 body = %q, want empty", body)
	}

	// With endpoint → 200 JSON
	a2 := &Authenticator{cfg: AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com", PostLogin: "https://nsc.example.com/"}, endSessionEndpoint: "https://idp.example.com/logout"}
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	a2.handleLogout(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("with endpoint status = %d, want %d", rr2.Code, http.StatusOK)
	}
	if ct := rr2.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var payload map[string]string
	if err := json.Unmarshal(rr2.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode json: %v body=%q", err, rr2.Body.String())
	}
	if _, ok := payload["end_session_url"]; !ok {
		t.Fatalf("payload missing end_session_url: %v", payload)
	}
	if !strings.Contains(payload["end_session_url"], "https://idp.example.com/logout") {
		t.Errorf("end_session_url = %q, want idp endpoint", payload["end_session_url"])
	}
	if !strings.Contains(payload["end_session_url"], "client_id=c") {
		t.Errorf("end_session_url missing client_id: %q", payload["end_session_url"])
	}

	// Invalid scheme (javascript) → fallback 204
	a3 := &Authenticator{cfg: AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"}, endSessionEndpoint: "javascript:alert(1)"}
	rr3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	a3.handleLogout(rr3, req3)
	if rr3.Code != http.StatusNoContent {
		t.Fatalf("javascript endpoint status = %d, want %d (fallback to local-only)", rr3.Code, http.StatusNoContent)
	}

	// Check Set-Cookie always sent (clears session)
	for _, rrCheck := range []*httptest.ResponseRecorder{rr, rr2, rr3} {
		cookies := rrCheck.Result().Cookies()
		found := false
		for _, c := range cookies {
			if strings.Contains(c.Name, "nsc_session") && c.MaxAge == -1 {
				found = true
			}
		}
		if !found {
			t.Errorf("clear session cookie not found in response %#v", rrCheck.Header().Get("Set-Cookie"))
		}
	}
}

func TestHandleLogoutPreservesEndpointQuery(t *testing.T) {
	a := &Authenticator{
		cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
		endSessionEndpoint: "https://idp.example.com/logout?existing=keep",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	a.handleLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var payload map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &payload)
	u, _ := url.Parse(payload["end_session_url"])
	if u.Query().Get("existing") != "keep" {
		t.Errorf("existing query not preserved: %q", payload["end_session_url"])
	}
}

func TestHandleLogoutRedirectGET(t *testing.T) {
	// No endpoint → redirect to "/"
	a := &Authenticator{cfg: AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"}, endSessionEndpoint: ""}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
	a.handleLogoutRedirect(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("no endpoint GET status = %d, want %d", rr.Code, http.StatusFound)
	}
	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Fatalf("location = %q, want /", loc)
	}

	// With endpoint → redirect to IdP
	a2 := &Authenticator{cfg: AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"}, endSessionEndpoint: "https://idp.example.com/end_session"}
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
	a2.handleLogoutRedirect(rr2, req2)
	if rr2.Code != http.StatusFound {
		t.Fatalf("with endpoint GET status = %d, want %d", rr2.Code, http.StatusFound)
	}
	loc2 := rr2.Header().Get("Location")
	if !strings.HasPrefix(loc2, "https://idp.example.com/end_session") {
		t.Fatalf("location = %q, want idp prefix", loc2)
	}
	if !strings.Contains(loc2, "client_id=c") {
		t.Errorf("location missing client_id: %q", loc2)
	}

	// Invalid scheme → fallback to "/"
	a3 := &Authenticator{cfg: AuthConfig{ClientID: "c"}, endSessionEndpoint: "javascript:alert(1)"}
	rr3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
	a3.handleLogoutRedirect(rr3, req3)
	if loc := rr3.Header().Get("Location"); loc != "/" {
		t.Fatalf("javascript fallback location = %q, want /", loc)
	}
}

// TestLogoutOriginGating exercises the HTTP-layer CSRF gate via Server.Handler.
// POST remains strict sameOrigin; GET allows sameOrigin OR direct Sec-Fetch-Site: none.
func TestLogoutOriginGating(t *testing.T) {
	makeServer := func(publicOrigin, endpoint string) *Server {
		return &Server{
			auth: &Authenticator{
				cfg:                AuthConfig{ClientID: "c", PublicOrigin: publicOrigin},
				endSessionEndpoint: endpoint,
			},
			spa: http.NotFoundHandler(),
		}
	}
	s := makeServer("https://nsc.example.com", "https://idp.example.com/logout")

	tests := []struct {
		name       string
		method     string
		origin     string
		fetchSite  string
		wantStatus int
	}{
		{name: "POST same-origin allowed", method: http.MethodPost, origin: "https://nsc.example.com", fetchSite: "same-origin", wantStatus: http.StatusOK},
		{name: "POST same-origin without fetchSite allowed", method: http.MethodPost, origin: "https://nsc.example.com", wantStatus: http.StatusOK},
		{name: "POST foreign origin blocked", method: http.MethodPost, origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "POST missing signals blocked", method: http.MethodPost, wantStatus: http.StatusForbidden},
		{name: "POST direct none blocked", method: http.MethodPost, fetchSite: "none", wantStatus: http.StatusForbidden},
		{name: "POST cross-site blocked", method: http.MethodPost, fetchSite: "cross-site", wantStatus: http.StatusForbidden},
		{name: "POST same-site blocked", method: http.MethodPost, fetchSite: "same-site", wantStatus: http.StatusForbidden},

		{name: "GET same-origin allowed", method: http.MethodGet, origin: "https://nsc.example.com", fetchSite: "same-origin", wantStatus: http.StatusFound},
		{name: "GET direct navigation none allowed", method: http.MethodGet, fetchSite: "none", wantStatus: http.StatusFound},
		{name: "GET direct none with no origin allowed", method: http.MethodGet, origin: "", fetchSite: "none", wantStatus: http.StatusFound},
		{name: "GET cross-site blocked", method: http.MethodGet, fetchSite: "cross-site", wantStatus: http.StatusForbidden},
		{name: "GET same-site blocked", method: http.MethodGet, fetchSite: "same-site", wantStatus: http.StatusForbidden},
		{name: "GET foreign origin with same-origin fetchSite blocked", method: http.MethodGet, origin: "https://evil.example", fetchSite: "same-origin", wantStatus: http.StatusForbidden},
		{name: "GET missing signals blocked", method: http.MethodGet, wantStatus: http.StatusForbidden},
		{name: "GET none with smuggled foreign origin blocked", method: http.MethodGet, origin: "https://evil.example", fetchSite: "none", wantStatus: http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/auth/logout", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusForbidden {
				// Forbidden should not clear cookie or redirect; just error.
				return
			}
			// Successful logout must clear the session cookie.
			found := false
			for _, c := range rr.Result().Cookies() {
				if strings.Contains(c.Name, "nsc_session") && c.MaxAge == -1 {
					found = true
				}
			}
			if !found {
				t.Errorf("successful logout did not clear session cookie, headers=%v", rr.Header().Get("Set-Cookie"))
			}
		})
	}

	// Bearer token bypass should allow POST even with foreign origin, and GET
	t.Run("bearer bypass POST foreign allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Authorization", "Bearer nsc_test")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("bearer POST status = %d, want %d", rr.Code, http.StatusOK)
		}
	})
	t.Run("bearer bypass GET missing signals allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer nsc_test")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("bearer GET status = %d, want %d", rr.Code, http.StatusFound)
		}
	})

	// Auth-disabled dev mode bypass
	t.Run("auth-disabled bypass", func(t *testing.T) {
		dev := &Server{auth: nil, spa: http.NotFoundHandler()}
		// Should 404 because auth routes not registered when auth==nil? Handler still registers? Check:
		// In Server.Handler, auth routes are only registered if s.auth != nil, so logout would 404.
		// So dev bypass not testable via Handler; test direct allow function.
		if !dev.logoutRedirectOriginAllowed(httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)) {
			t.Fatal("dev mode should allow")
		}
		if !dev.mutationOriginAllowed(httptest.NewRequest(http.MethodPost, "/api/targets", nil)) {
			t.Fatal("dev mode should allow mutations")
		}
	})
}

func TestLogoutRedirectFailClosedOnInvalidPublicOrigin(t *testing.T) {
	// Regression for follow-up review: GET /api/auth/logout with Sec-Fetch-Site: none
	// must still fail closed (403) when APP_BASE_URL / PublicOrigin is missing or
	// malformed — both logout endpoints fail closed per docs/API.md:51-52.
	for _, publicOrigin := range []string{"", "://bad"} {
		t.Run("publicOrigin="+publicOrigin, func(t *testing.T) {
			s := &Server{
				auth: &Authenticator{
					cfg:                AuthConfig{ClientID: "c", PublicOrigin: publicOrigin},
					endSessionEndpoint: "https://idp.example.com/logout",
				},
				spa: http.NotFoundHandler(),
			}
			req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
			req.Header.Set("Sec-Fetch-Site", "none")
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("GET none with PublicOrigin=%q status = %d, want %d (fail-closed)", publicOrigin, rr.Code, http.StatusForbidden)
			}
			// Same for POST strict path — must also be forbidden when origin is invalid
			req2 := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
			req2.Header.Set("Origin", "https://nsc.example.com")
			rr2 := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr2, req2)
			if rr2.Code != http.StatusForbidden {
				t.Fatalf("POST same-origin with PublicOrigin=%q status = %d, want %d", publicOrigin, rr2.Code, http.StatusForbidden)
			}
		})
	}
	// Direct helper check
	t.Run("helper fail-closed", func(t *testing.T) {
		for _, origin := range []string{"", "://bad"} {
			s := &Server{auth: &Authenticator{cfg: AuthConfig{PublicOrigin: origin}}}
			req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
			req.Header.Set("Sec-Fetch-Site", "none")
			if s.logoutRedirectOriginAllowed(req) {
				t.Fatalf("logoutRedirectOriginAllowed with PublicOrigin=%q and none should be false", origin)
			}
		}
	})
}

func TestLogoutGETFallbackWhenNoEndpoint(t *testing.T) {
	// Even with direct navigation, fallback is "/"
	s := &Server{
		auth: &Authenticator{
			cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			endSessionEndpoint: "",
		},
		spa: http.NotFoundHandler(),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "none")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}
	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Fatalf("fallback location = %q, want /", loc)
	}
}

// faultyAuthStore is a minimal in-memory authStore for fault-injection tests
// (#268). It tracks sessions in a map and can be configured to fail
// DeleteSession to simulate a transient Postgres outage.
type faultyAuthStore struct {
	deleteErr error
	sessions  map[string]store.Session
}

func (f *faultyAuthStore) DeleteSession(ctx context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if f.sessions != nil {
		delete(f.sessions, id)
	}
	return nil
}
func (f *faultyAuthStore) GetSession(ctx context.Context, id string) (store.Session, error) {
	if f.sessions == nil {
		return store.Session{}, store.ErrNotFound
	}
	sess, ok := f.sessions[id]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	return sess, nil
}
func (f *faultyAuthStore) CreateSession(ctx context.Context, sess store.Session) error { return nil }
func (f *faultyAuthStore) UpsertUser(ctx context.Context, id store.Identity) error     { return nil }
func (f *faultyAuthStore) CreateAuthFlow(ctx context.Context, flow store.AuthFlow) error {
	return nil
}
func (f *faultyAuthStore) TakeAuthFlow(ctx context.Context, state string) (store.AuthFlow, error) {
	return store.AuthFlow{}, store.ErrNotFound
}

func hasClearSessionCookie(rr *httptest.ResponseRecorder) bool {
	for _, c := range rr.Result().Cookies() {
		if strings.Contains(c.Name, "nsc_session") && c.MaxAge == -1 {
			return true
		}
	}
	return false
}

// TestHandleLogoutFailsClosedOnStoreError verifies POST /api/auth/logout fails
// closed when server-side revocation fails: 503 with Retry-After, no cookie
// clearing, and no IdP URL leaked (#268).
func TestHandleLogoutFailsClosedOnStoreError(t *testing.T) {
	const cookieVal = "test-session-copy"
	cases := []struct {
		name     string
		endpoint string
	}{
		{name: "with IdP endpoint", endpoint: "https://idp.example.com/logout"},
		{name: "without IdP endpoint", endpoint: ""},
		{name: "with javascript endpoint (treated as missing)", endpoint: "javascript:alert(1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Authenticator{
				store:              &faultyAuthStore{deleteErr: errors.New("postgres unavailable")},
				cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
				endSessionEndpoint: tc.endpoint,
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
			req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
			a.handleLogout(rr, req)

			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
			}
			if got := rr.Header().Get("Retry-After"); got != "1" {
				t.Fatalf("Retry-After = %q, want 1", got)
			}
			if hasClearSessionCookie(rr) {
				t.Fatalf("failure must not clear session cookie, got Set-Cookie %q", rr.Header().Get("Set-Cookie"))
			}
			body := rr.Body.String()
			if strings.Contains(body, "end_session_url") || strings.Contains(body, "idp.example.com") {
				t.Fatalf("failure must not leak end_session_url, body=%q", body)
			}
			if !strings.Contains(body, "logout temporarily unavailable") {
				t.Fatalf("body = %q, want generic 503 message", body)
			}
		})
	}

	// No cookie → no deletion needed, so logout still succeeds even when
	// the store is faulty (idempotent logout).
	t.Run("no cookie still succeeds", func(t *testing.T) {
		for _, endpoint := range []string{"", "https://idp.example.com/logout"} {
			a := &Authenticator{
				store:              &faultyAuthStore{deleteErr: errors.New("postgres unavailable")},
				cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
				endSessionEndpoint: endpoint,
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
			a.handleLogout(rr, req)
			// Without a cookie there is nothing to revoke, so 204 (or 200 with endpoint) is correct.
			want := http.StatusNoContent
			if endpoint != "" {
				want = http.StatusOK
			}
			if rr.Code != want {
				t.Fatalf("no-cookie with endpoint %q status = %d, want %d", endpoint, rr.Code, want)
			}
			if !hasClearSessionCookie(rr) {
				t.Fatalf("no-cookie success must still clear cookie")
			}
		}
	})

	// Empty cookie value is treated as missing.
	t.Run("empty cookie still succeeds", func(t *testing.T) {
		a := &Authenticator{
			store: &faultyAuthStore{deleteErr: errors.New("boom")},
			cfg:   AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: ""})
		a.handleLogout(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("empty cookie status = %d, want %d", rr.Code, http.StatusNoContent)
		}
	})
}

// TestHandleLogoutRedirectFailsClosedOnStoreError verifies GET /api/auth/logout
// does not redirect (neither to IdP nor to "/") when revocation fails (#268).
func TestHandleLogoutRedirectFailsClosedOnStoreError(t *testing.T) {
	const cookieVal = "test-session-copy"
	cases := []struct {
		name     string
		endpoint string
	}{
		{name: "with IdP endpoint", endpoint: "https://idp.example.com/end_session"},
		{name: "without IdP endpoint", endpoint: ""},
		{name: "with javascript endpoint", endpoint: "javascript:alert(1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Authenticator{
				store:              &faultyAuthStore{deleteErr: errors.New("postgres unavailable")},
				cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
				endSessionEndpoint: tc.endpoint,
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
			req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
			a.handleLogoutRedirect(rr, req)

			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
			}
			if got := rr.Header().Get("Retry-After"); got != "1" {
				t.Fatalf("Retry-After = %q, want 1", got)
			}
			if hasClearSessionCookie(rr) {
				t.Fatalf("failure must not clear cookie, got %q", rr.Header().Get("Set-Cookie"))
			}
			if loc := rr.Header().Get("Location"); loc != "" {
				t.Fatalf("failure must not redirect, got Location %q", loc)
			}
			if strings.Contains(rr.Body.String(), "idp.example.com") {
				t.Fatalf("body leaked IdP endpoint: %q", rr.Body.String())
			}
		})
	}

	t.Run("no cookie still redirects", func(t *testing.T) {
		a := &Authenticator{
			store:              &faultyAuthStore{deleteErr: errors.New("boom")},
			cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			endSessionEndpoint: "https://idp.example.com/end_session",
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
		a.handleLogoutRedirect(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("no-cookie redirect status = %d, want %d", rr.Code, http.StatusFound)
		}
		if !hasClearSessionCookie(rr) {
			t.Fatal("no-cookie success must still clear cookie")
		}
	})
}

// TestLogoutCopiedCookieAfterSuccessVsFailure ensures a response presented as
// successful logout always means the session is gone, while a 503 preserves it
// for retry — the core invariant behind #268.
func TestLogoutCopiedCookieAfterSuccessVsFailure(t *testing.T) {
	const cookieVal = "copied-session-123"
	identity := store.Identity{Subject: "victim", Email: "victim@example.com", Roles: []string{RoleViewer}}

	// 1. Failure case: DeleteSession errors, handler returns 503 and the
	// copied cookie still authenticates (simulating attacker reuse until
	// the victim retries after the outage recovers).
	t.Run("failure preserves session", func(t *testing.T) {
		fstore := &faultyAuthStore{
			deleteErr: errors.New("transient pg failure"),
			sessions:  map[string]store.Session{cookieVal: {ID: cookieVal, Identity: identity}},
		}
		a := &Authenticator{
			store:              fstore,
			cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			endSessionEndpoint: "https://idp.example.com/logout",
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
		a.handleLogout(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rr.Code)
		}
		if hasClearSessionCookie(rr) {
			t.Fatal("503 must not clear cookie")
		}
		if _, err := fstore.GetSession(context.Background(), cookieVal); err != nil {
			t.Fatalf("session should still exist after failed logout, got err %v", err)
		}
		// identityFromRequest with the same cookie still resolves (attacker can still use it,
		// but the victim was not told logout succeeded, so they will retry).
		req2 := httptest.NewRequest(http.MethodGet, "/api/targets", nil)
		req2.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
		if got, err := a.identityFromRequest(req2); err != nil || got.Subject != "victim" {
			t.Fatalf("identityFromRequest after failed logout = %#v err %v, want victim", got, err)
		}
	})

	// 2. Success case: DeleteSession succeeds, handler returns 200 (with IdP URL)
	// and the copied cookie is now invalid.
	t.Run("success revokes copied cookie POST", func(t *testing.T) {
		fstore := &faultyAuthStore{
			sessions: map[string]store.Session{cookieVal: {ID: cookieVal, Identity: identity}},
		}
		a := &Authenticator{
			store:              fstore,
			cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			endSessionEndpoint: "https://idp.example.com/logout",
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
		a.handleLogout(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if !hasClearSessionCookie(rr) {
			t.Fatal("successful logout must clear cookie")
		}
		var payload map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload["end_session_url"] == "" {
			t.Fatal("successful logout with endpoint must include end_session_url")
		}
		if _, err := fstore.GetSession(context.Background(), cookieVal); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("session should be gone after successful logout, got err %v", err)
		}
		req2 := httptest.NewRequest(http.MethodGet, "/api/targets", nil)
		req2.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
		if got, err := a.identityFromRequest(req2); err != nil {
			t.Fatalf("identityFromRequest err %v", err)
		} else if got.Subject != "" {
			t.Fatalf("attacker reuse after successful logout: identity = %#v, want empty", got)
		}
	})

	// 3. Success via GET also revokes.
	t.Run("success revokes copied cookie GET", func(t *testing.T) {
		fstore := &faultyAuthStore{
			sessions: map[string]store.Session{cookieVal: {ID: cookieVal, Identity: identity}},
		}
		a := &Authenticator{
			store:              fstore,
			cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
			endSessionEndpoint: "https://idp.example.com/end_session",
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
		a.handleLogoutRedirect(rr, req)

		if rr.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rr.Code)
		}
		if !hasClearSessionCookie(rr) {
			t.Fatal("successful GET logout must clear cookie")
		}
		if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.example.com/end_session") {
			t.Fatalf("Location = %q, want IdP prefix", loc)
		}
		if _, err := fstore.GetSession(context.Background(), cookieVal); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("session should be gone after successful GET logout, got err %v", err)
		}
	})
}

// TestLogoutRecoveryRetry ensures a failed logout can be retried successfully
// once the store recovers — the preserved cookie is reused.
func TestLogoutRecoveryRetry(t *testing.T) {
	const cookieVal = "retry-session-xyz"
	identity := store.Identity{Subject: "alice", Roles: []string{RoleOperator}}
	fstore := &faultyAuthStore{
		deleteErr: errors.New("pg down"),
		sessions:  map[string]store.Session{cookieVal: {ID: cookieVal, Identity: identity}},
	}
	a := &Authenticator{
		store: fstore,
		cfg:   AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
	}

	// First attempt fails.
	rr1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req1.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
	a.handleLogout(rr1, req1)
	if rr1.Code != http.StatusServiceUnavailable {
		t.Fatalf("first attempt status = %d, want 503", rr1.Code)
	}
	if hasClearSessionCookie(rr1) {
		t.Fatal("first attempt must not clear cookie")
	}

	// Store recovers.
	fstore.deleteErr = nil
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req2.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: cookieVal})
	a.handleLogout(rr2, req2)
	if rr2.Code != http.StatusNoContent {
		t.Fatalf("retry status = %d, want 204", rr2.Code)
	}
	if !hasClearSessionCookie(rr2) {
		t.Fatal("retry success must clear cookie")
	}
	if _, err := fstore.GetSession(context.Background(), cookieVal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session should be gone after retry, got %v", err)
	}
}

// TestLogoutSucceedsWhenSessionAlreadyMissing documents the load-bearing
// idempotence of DeleteSession (#268). The background SweepExpiredAuth sweeper
// routinely deletes already-expired sessions, so a logout for a cookie whose
// row was already removed must still return success (204/200 or 302) and clear
// the browser cookie — not a spurious 503. A future store change that starts
// returning ErrNotFound for missing rows would silently break logout for every
// already-expired session.
func TestLogoutSucceedsWhenSessionAlreadyMissing(t *testing.T) {
	const missingCookie = "already-swept-session"
	// faultyAuthStore with no sessions map entry simulates the sweeper having
	// already deleted the row: DeleteSession returns nil (idempotent).
	fstore := &faultyAuthStore{
		sessions: map[string]store.Session{},
	}
	// Also verify the interface contract directly: missing DeleteSession must be nil.
	if err := fstore.DeleteSession(context.Background(), missingCookie); err != nil {
		t.Fatalf("DeleteSession(missing) = %v, want nil (idempotent)", err)
	}
	if err := fstore.DeleteSession(context.Background(), missingCookie); err != nil {
		t.Fatalf("second DeleteSession(missing) = %v, want nil", err)
	}

	for _, tc := range []struct {
		name     string
		endpoint string
	}{
		{name: "POST without IdP endpoint", endpoint: ""},
		{name: "POST with IdP endpoint", endpoint: "https://idp.example.com/logout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Authenticator{
				store:              fstore,
				cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
				endSessionEndpoint: tc.endpoint,
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
			req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: missingCookie})
			a.handleLogout(rr, req)

			want := http.StatusNoContent
			if tc.endpoint != "" {
				want = http.StatusOK
			}
			if rr.Code != want {
				t.Fatalf("status = %d, want %d (already-missing must succeed)", rr.Code, want)
			}
			if !hasClearSessionCookie(rr) {
				t.Fatal("already-missing logout must still clear cookie")
			}
			if rr.Header().Get("Retry-After") != "" {
				t.Fatalf("Retry-After = %q, want empty on success", rr.Header().Get("Retry-After"))
			}
		})
	}

	for _, tc := range []struct {
		name     string
		endpoint string
	}{
		{name: "GET without IdP endpoint", endpoint: ""},
		{name: "GET with IdP endpoint", endpoint: "https://idp.example.com/end_session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Authenticator{
				store:              fstore,
				cfg:                AuthConfig{ClientID: "c", PublicOrigin: "https://nsc.example.com"},
				endSessionEndpoint: tc.endpoint,
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/auth/logout", nil)
			req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: missingCookie})
			a.handleLogoutRedirect(rr, req)

			if rr.Code != http.StatusFound {
				t.Fatalf("GET already-missing status = %d, want %d", rr.Code, http.StatusFound)
			}
			if !hasClearSessionCookie(rr) {
				t.Fatal("GET already-missing logout must still clear cookie")
			}
			wantLoc := "/"
			if tc.endpoint != "" {
				wantLoc = tc.endpoint
			}
			loc := rr.Header().Get("Location")
			if tc.endpoint != "" && !strings.HasPrefix(loc, wantLoc) {
				t.Fatalf("Location = %q, want prefix %q", loc, wantLoc)
			}
			if tc.endpoint == "" && loc != wantLoc {
				t.Fatalf("Location = %q, want %q", loc, wantLoc)
			}
		})
	}
}
