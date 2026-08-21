// Package web embeds the built React SPA and serves it with client-route
// fallback. The dist/ directory is produced by `npm run build` (Vite) and is
// git-ignored; only an empty dist/.gitkeep is committed, so `//go:embed all:dist`
// has a non-empty directory and `go build` works on a fresh clone before the SPA
// is built. With no build to serve, Handler falls back to notBuiltHTML — the same
// notice the previously committed placeholder index.html carried.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// notBuiltHTML is served when dist holds no index.html — i.e. the binary was built
// without building the SPA first. It lives here rather than in a committed
// dist/index.html so that no file Vite overwrites is tracked by git.
const notBuiltHTML = `<!doctype html>
<meta charset="utf-8">
<title>Nuclei Security Center</title>
<p>Frontend not built. Run <code>npm ci &amp;&amp; npm run build</code> in <code>web/</code>.</p>
`

// SecurityHeadersCSP is the tightly scoped Content-Security-Policy for the
// same-origin SPA + JSON API. It is the single source of truth for the
// policy — both the backend middleware and this SPA handler use it, so a
// future tweak cannot silently diverge between the two packages.
const SecurityHeadersCSP = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'"

// SetSecurityHeaders applies the baseline hardening headers (CSP,
// anti-framing, anti-MIME-sniffing, referrer policy) to h. The backend
// middleware reuses this helper so the SPA handler and the API share the
// exact same values.
func SetSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", SecurityHeadersCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// Handler serves the embedded SPA build. Requests that don't map to a real asset
// fall back to index.html so client-side routing works on deep links and refresh.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("web: sub dist: " + err.Error())
	}
	return handlerFor(sub)
}

// handlerFor is Handler's logic over any filesystem, so the no-build fallback is
// testable without depending on whether dist/ happens to hold a real build.
func handlerFor(fsys fs.FS) http.Handler {
	index, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		// No SPA build embedded. Serving the notice beats failing to start: a
		// Go-only dev can still run the backend and drive the API without a Node
		// toolchain, which is what the committed placeholder used to allow.
		index = []byte(notBuiltHTML)
	}
	fileServer := http.FileServer(http.FS(fsys))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Harden the SPA even when the handler is used standalone (e.g. in
		// web tests). In production the backend's securityHeaders middleware
		// has already set the same values via the shared helper, so this is
		// an idempotent overwrite with identical values — not a divergent
		// policy.
		SetSecurityHeaders(w.Header())
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(fsys, p); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Client route: serve the SPA shell.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}
