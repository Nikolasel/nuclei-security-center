package backend

import (
	"net/http"
	"net/url"
	"strings"
)

// mutationOriginAllowed protects cookie-authenticated mutations from cross-site
// requests. Bearer-token callers are explicit, non-ambient callers and do not
// need a browser origin header; auth-disabled development has no session
// identity to protect. A missing or malformed configured origin fails closed.
func (s *Server) mutationOriginAllowed(r *http.Request) bool {
	if s.auth == nil || bearerTokenPresent(r) {
		return true
	}
	return sameOriginRequest(r, s.auth.cfg.PublicOrigin)
}

// sameOrigin protects the cookie-backed logout endpoint, which intentionally
// does not use mutation's role/audit wrapper because logging out does not
// require an authenticated identity or mutate application data.
func (s *Server) sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.mutationOriginAllowed(r) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// logoutRedirectOriginAllowed is the CSRF gate for GET /api/auth/logout.
//
// POST /api/auth/logout stays strict sameOrigin (Sec-Fetch-Site: same-origin or
// exact Origin match). GET additionally allows direct browser navigations —
// address-bar or bookmark visits that browsers signal as Sec-Fetch-Site: none
// with no Origin — so a user who navigates to /api/auth/logout directly still
// terminates both the local session and, when advertised, the IdP SSO cookie.
// Site-controlled cross-origin navigations (Sec-Fetch-Site: cross-site or
// same-site, e.g. an attacker <a> link) remain blocked, preserving logout CSRF
// protection. Bearer-token callers and auth-disabled dev mode bypass the check
// like mutationOriginAllowed.
func (s *Server) logoutRedirectOriginAllowed(r *http.Request) bool {
	if s.auth == nil || bearerTokenPresent(r) {
		return true
	}
	if sameOriginRequest(r, s.auth.cfg.PublicOrigin) {
		return true
	}
	// Direct user navigation: no Origin header and Sec-Fetch-Site: none.
	// Forbidden headers cannot be set by site-controlled fetch(), so only a
	// genuine top-level browser navigation can produce this signal.
	// Explicitly fail closed when the configured public origin is missing or
	// malformed — sameOriginRequest would reject it, so the `none` exception
	// must not bypass that. Both logout endpoints fail closed per docs/API.md.
	if len(r.Header.Values("Origin")) == 0 && strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "none") {
		if _, ok := canonicalOrigin(s.auth.cfg.PublicOrigin, true); !ok {
			return false
		}
		return true
	}
	return false
}

func (s *Server) sameOriginOrDirect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.logoutRedirectOriginAllowed(r) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func bearerTokenPresent(r *http.Request) bool {
	_, ok := bearerToken(r)
	return ok
}

// sameOriginRequest accepts an exact Origin match. When browsers omit Origin,
// the Fetch Metadata header is an acceptable same-origin signal. same-site is
// deliberately not accepted: sibling subdomains share a site but can still be
// attacker-controlled, which is the gap this guard closes.
func sameOriginRequest(r *http.Request, configured string) bool {
	expected, ok := canonicalOrigin(configured, true)
	if !ok {
		return false
	}

	origins := r.Header.Values("Origin")
	if len(origins) > 1 {
		return false
	}
	if len(origins) == 1 {
		origin, ok := canonicalOrigin(origins[0], false)
		if !ok || origin != expected {
			return false
		}
		if fetchSite := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); fetchSite != "" && !strings.EqualFold(fetchSite, "same-origin") {
			return false
		}
		return true
	}

	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "same-origin")
}

// canonicalOrigin reduces a browser origin or configured public URL to a
// scheme/host/port tuple. Configured URLs may include a path because
// APP_BASE_URL is also used to build redirects; request Origin values may only
// contain an optional root slash.
func canonicalOrigin(raw string, configured bool) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if !configured && u.Path != "" && u.Path != "/" {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", false
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, true
}
