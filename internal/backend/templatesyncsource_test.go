package backend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestValidateTemplateSyncRepo(t *testing.T) {
	valid := []string{
		"https://github.com/projectdiscovery/nuclei-templates.git",
		"https://user:secret@github.com/projectdiscovery/nuclei-templates.git",
		"https://token@github.com/projectdiscovery/nuclei-templates.git?token_query=1",
		"SSH://git@github.com/projectdiscovery/nuclei-templates.git",
		"git://github.com/projectdiscovery/nuclei-templates.git",
		"ssh://git@internal.example.test:2222/templates.git",
	}
	for _, repo := range valid {
		if got, err := validateTemplateSyncRepo(repo); err != nil {
			t.Errorf("validateTemplateSyncRepo(%q) = error %v, want accepted", repo, err)
		} else if got != repo {
			t.Errorf("validateTemplateSyncRepo(%q) = %q, want the trimmed value unchanged", repo, got)
		}
	}
	invalid := []string{
		"",
		"   ",
		"file:///etc/templates",
		"file://projectdiscovery/nuclei-templates",
		"/tmp/nuclei-templates",
		"../relative/repo",
		"http://github.com/projectdiscovery/nuclei-templates.git",
		"ftp://github.com/projectdiscovery/nuclei-templates.git",
		"git@github.com:projectdiscovery/nuclei-templates.git",
		"https:///no-host/templates.git",
		"https://",
	}
	for _, repo := range invalid {
		if _, err := validateTemplateSyncRepo(repo); err == nil {
			t.Errorf("validateTemplateSyncRepo(%q) = accepted, want rejected", repo)
		}
	}
}

func TestValidateTemplateSyncRef(t *testing.T) {
	valid := []string{
		"latest",
		"main",
		"v9.9.9",
		"dev-preview-branch",
		"feature/cool-branch",
		"refs/tags/v1.2.3",
		"refs/heads/main",
		"1234567",
		"abcdef0123456789abcdef0123456789abcdef01",
		"ABCDEF0123456789abcdef0123456789abcdef01",
		// Braces are ordinary characters; only the @{ sequence is special.
		"at{name",
	}
	for _, ref := range valid {
		got, err := validateTemplateSyncRef(ref)
		if err != nil {
			t.Errorf("validateTemplateSyncRef(%q) = error %v, want accepted", ref, err)
			continue
		}
		if got != ref {
			t.Errorf("validateTemplateSyncRef(%q) = %q", ref, got)
		}
	}
	invalid := []string{
		"",
		" ",
		"..",
		"a/b..c",
		"with space",
		"tilde~name",
		"caret^name",
		"colon:name",
		"question?name",
		"star*name",
		"bracket[name",
		"trailing.dot.",
		".leadingdot",
		"a//b",
		"/leading-slash",
		"trailing-slash/",
		"endswith.lock",
		".lock",
		// The @{ sequence is rejected by git-check-ref-format everywhere in
		// the name, not only at the start.
		"ab@{cd",
	}
	for _, ref := range invalid {
		if _, err := validateTemplateSyncRef(ref); err == nil {
			t.Errorf("validateTemplateSyncRef(%q) = accepted, want rejected", ref)
		}
	}
}

// effectiveTemplateSyncSource merges the request over the stored source and
// writes 400 itself for an invalid repo/ref.
func TestEffectiveTemplateSyncSourceMerge(t *testing.T) {
	s := &Server{}
	stored := store.TemplateSyncSource{Repo: "https://github.com/projectdiscovery/nuclei-templates.git", Ref: "latest"}
	cases := []struct {
		name         string
		req          templateSyncSourceRequest
		wantRepo     string
		wantRef      string
		wantStatus   int
		wantContains string
	}{
		{
			name:     "omitted repo keeps stored, ref replaces",
			req:      templateSyncSourceRequest{Ref: "main"},
			wantRepo: stored.Repo, wantRef: "main", wantStatus: http.StatusOK,
		},
		{
			name:     "explicit empty repo disables",
			req:      templateSyncSourceRequest{Repo: strPtr(""), Ref: "latest"},
			wantRepo: "", wantRef: "latest", wantStatus: http.StatusOK,
		},
		{
			name:         "invalid repo rejected",
			req:          templateSyncSourceRequest{Repo: strPtr("file:///etc/passwd"), Ref: "main"},
			wantStatus:   http.StatusBadRequest,
			wantContains: "https, ssh, or git",
		},
		{
			name:         "relative repo rejected",
			req:          templateSyncSourceRequest{Repo: strPtr("nuclei-templates"), Ref: "main"},
			wantStatus:   http.StatusBadRequest,
			wantContains: "absolute URL",
		},
		{
			name:         "empty ref rejected",
			req:          templateSyncSourceRequest{Ref: "  "},
			wantStatus:   http.StatusBadRequest,
			wantContains: "ref is required",
		},
		{
			name:         "invalid ref rejected",
			req:          templateSyncSourceRequest{Ref: "bad ref"},
			wantStatus:   http.StatusBadRequest,
			wantContains: "invalid git ref",
		},
		{
			// A short SHA is indistinguishable from a legal ref name, so the
			// format check accepts it; the save-time dry run decides whether
			// it actually resolves.
			name:     "short sha accepted as ref name",
			req:      templateSyncSourceRequest{Ref: "abc"},
			wantRepo: stored.Repo, wantRef: "abc", wantStatus: http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			got, ok := s.effectiveTemplateSyncSource(rr, stored, tc.req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d body %q", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if ok != (tc.wantStatus == http.StatusOK) {
				t.Fatalf("ok = %v, want %v", ok, tc.wantStatus == http.StatusOK)
			}
			if tc.wantStatus != http.StatusOK {
				if !strings.Contains(rr.Body.String(), tc.wantContains) {
					t.Fatalf("body %q missing %q", rr.Body.String(), tc.wantContains)
				}
				return
			}
			if got.Repo != tc.wantRepo || got.Ref != tc.wantRef {
				t.Fatalf("source = %+v, want repo %q ref %q", got, tc.wantRepo, tc.wantRef)
			}
		})
	}
}

// The preview dry run is a cookie-authenticated POST that triggers a fetch, so
// a foreign origin is refused even before the role check output matters.
func TestPreviewTemplateSyncSourceOriginGuard(t *testing.T) {
	s := &Server{
		auth: &Authenticator{cfg: AuthConfig{CookieName: "nsc_session", PublicOrigin: "http://localhost:8080"}},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/templates/sync/preview", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	s.handlePreviewTemplateSyncSource(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("foreign origin preview status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestTemplateSyncConfigUnavailableWithoutWiring(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	s.handleUpdateTemplateSyncConfig(rr, httptest.NewRequest(http.MethodPut, "/api/templates/sync/config", strings.NewReader(`{"ref":"latest"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.handlePreviewTemplateSyncSource(rr, httptest.NewRequest(http.MethodPost, "/api/templates/sync/preview", strings.NewReader(`{"ref":"latest"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}
