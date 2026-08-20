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
