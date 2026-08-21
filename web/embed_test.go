package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// built is a stand-in for a real Vite build: an index.html plus a hashed asset.
func built() fstest.MapFS {
	return fstest.MapFS{
		"index.html":             &fstest.MapFile{Data: []byte("<!doctype html><div id=root></div>")},
		"assets/index-abc123.js": &fstest.MapFile{Data: []byte("console.log(1)")},
		"favicon.ico":            &fstest.MapFile{Data: []byte("icon")},
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHandlerServesBuild(t *testing.T) {
	h := handlerFor(built())

	if rec := get(t, h, "/"); !strings.Contains(rec.Body.String(), "id=root") {
		t.Fatalf("/ = %q, want the built index.html", rec.Body.String())
	}
	if rec := get(t, h, "/assets/index-abc123.js"); rec.Body.String() != "console.log(1)" {
		t.Fatalf("asset = %q, want the real file", rec.Body.String())
	}
}

// A deep link is a client route, not a file: it must fall back to the SPA shell so
// a refresh on /findings/123 doesn't 404.
func TestHandlerDeepLinkFallsBackToShell(t *testing.T) {
	rec := get(t, handlerFor(built()), "/findings/123")
	if !strings.Contains(rec.Body.String(), "id=root") {
		t.Fatalf("deep link = %q, want the SPA shell", rec.Body.String())
	}
}

// The case that motivates handlerFor: dist holds only .gitkeep because the SPA
// wasn't built. This must serve the notice rather than panic, so a Go-only dev can
// still run the backend and drive the API without a Node toolchain.
func TestHandlerWithoutBuildServesNotice(t *testing.T) {
	onlyGitkeep := fstest.MapFS{".gitkeep": &fstest.MapFile{}}

	for _, path := range []string{"/", "/findings"} {
		rec := get(t, handlerFor(onlyGitkeep), path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Frontend not built") {
			t.Fatalf("%s = %q, want the not-built notice", path, rec.Body.String())
		}
	}
}

// Handler() must work against the real embedded FS whether or not dist/ currently
// holds a build — that's the property the committed .gitkeep exists to guarantee.
func TestHandlerFromEmbeddedFSDoesNotPanic(t *testing.T) {
	if rec := get(t, Handler(), "/"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func assertSecurityHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatalf("missing Content-Security-Policy header")
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q, want frame-ancestors 'none'", csp)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got == "" {
		t.Fatalf("missing Referrer-Policy header")
	}
}

func TestHandlerSecurityHeaders(t *testing.T) {
	h := handlerFor(built())

	for _, path := range []string{"/", "/assets/index-abc123.js", "/findings/123"} {
		rec := get(t, h, path)
		assertSecurityHeaders(t, rec)
	}

	// The no-build fallback must also be hardened.
	onlyGitkeep := fstest.MapFS{".gitkeep": &fstest.MapFile{}}
	for _, path := range []string{"/", "/findings"} {
		rec := get(t, handlerFor(onlyGitkeep), path)
		assertSecurityHeaders(t, rec)
	}
}
