package backend

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"golang.org/x/oauth2"
)

type recordingAuthStore struct {
	flows int
}

func (r *recordingAuthStore) CreateAuthFlow(context.Context, store.AuthFlow) error {
	r.flows++
	return nil
}
func (r *recordingAuthStore) TakeAuthFlow(context.Context, string) (store.AuthFlow, error) {
	return store.AuthFlow{}, store.ErrNotFound
}
func (r *recordingAuthStore) UpsertUser(context.Context, store.Identity) error { return nil }
func (r *recordingAuthStore) CreateSession(context.Context, store.Session) error {
	return nil
}
func (r *recordingAuthStore) GetSession(context.Context, string) (store.Session, error) {
	return store.Session{}, store.ErrNotFound
}
func (r *recordingAuthStore) DeleteSession(context.Context, string) error { return nil }

func testCanonicalHostServer(t *testing.T, publicOrigin string, st authStore) http.Handler {
	t.Helper()
	if st == nil {
		st = &recordingAuthStore{}
	}
	s := &Server{
		auth: &Authenticator{
			store: st,
			cfg:   AuthConfig{PublicOrigin: publicOrigin},
			oauth: &oauth2.Config{
				ClientID:    "test-client",
				RedirectURL: strings.TrimSuffix(publicOrigin, "/") + "/api/auth/callback",
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://idp.test/authorize",
					TokenURL: "https://idp.test/token",
				},
				Scopes: []string{"openid"},
			},
			log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		spa: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("spa"))
		}),
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return s.Handler()
}

func TestLoginRedirectsOffLoopbackAliasBeforeStartingOIDC(t *testing.T) {
	st := &recordingAuthStore{}
	h := testCanonicalHostServer(t, "http://localhost:8080", st)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/auth/login?return_to=/findings", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}
	if got := rr.Header().Get("Location"); got != "http://localhost:8080/api/auth/login?return_to=/findings" {
		t.Fatalf("Location = %q, want canonical login URL", got)
	}
	if cookies := rr.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("mismatched-host login set cookies before redirect: %v", cookies)
	}
	if st.flows != 0 {
		t.Fatalf("auth flows created = %d, want 0 (redirect must run before OIDC start)", st.flows)
	}
}

func TestLoginOnCanonicalHostStartsOIDC(t *testing.T) {
	st := &recordingAuthStore{}
	h := testCanonicalHostServer(t, "http://localhost:8080", st)
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/auth/login", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("canonical-host login status = %d, want %d", rr.Code, http.StatusFound)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.test/authorize") {
		t.Fatalf("Location = %q, want IdP authorize URL", loc)
	}
	if st.flows != 1 {
		t.Fatalf("auth flows created = %d, want 1", st.flows)
	}
}

func TestSPARedirectsOffLoopbackAlias(t *testing.T) {
	h := testCanonicalHostServer(t, "http://localhost:8080", nil)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/nodes", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}
	if got := rr.Header().Get("Location"); got != "http://localhost:8080/nodes" {
		t.Fatalf("Location = %q, want http://localhost:8080/nodes", got)
	}
	if body := rr.Body.String(); strings.Contains(body, "spa") {
		t.Fatal("SPA rendered on the non-canonical host")
	}
}

func TestSPAServesOnCanonicalHost(t *testing.T) {
	h := testCanonicalHostServer(t, "http://localhost:8080", nil)
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/nodes", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Body.String(); got != "spa" {
		t.Fatalf("body = %q, want spa", got)
	}
}

func TestHealthzDoesNotCanonicalHostRedirect(t *testing.T) {
	h := testCanonicalHostServer(t, "http://localhost:8080", nil)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("healthz redirected to %q", loc)
	}
}

func TestAPIDoesNotCanonicalHostRedirect(t *testing.T) {
	h := testCanonicalHostServer(t, "http://localhost:8080", nil)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/targets", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code == http.StatusFound {
		t.Fatalf("API redirected to %q; service-account callers may use an IP", rr.Header().Get("Location"))
	}
}

func TestAuthDisabledDoesNotCanonicalHostRedirect(t *testing.T) {
	s := &Server{
		spa: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("spa"))
		}),
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("auth-disabled status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestCanonicalHostRedirectDoesNotConsumeLoginAdmission(t *testing.T) {
	st := &recordingAuthStore{}
	a := &Authenticator{
		store: st,
		cfg: AuthConfig{
			PublicOrigin:    "http://localhost:8080",
			LoginBurst:      1,
			LoginRate:       0.000001,
			LoginMaxClients: 8,
		},
		oauth: &oauth2.Config{
			ClientID: "test-client",
			Endpoint: oauth2.Endpoint{AuthURL: "https://idp.test/authorize", TokenURL: "https://idp.test/token"},
			Scopes:   []string{"openid"},
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s := &Server{auth: a, spa: http.NotFoundHandler(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/auth/login", nil)
	req.RemoteAddr = "192.0.2.8:43122"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}
	if st.flows != 0 {
		t.Fatalf("redirect created %d auth flows, want 0", st.flows)
	}

	// Same peer on the canonical host must still have its burst available —
	// the redirect must not mint a flow or take a limiter token.
	canonical := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/auth/login", nil)
	canonical.RemoteAddr = "192.0.2.8:43122"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, canonical)
	if rr2.Code == http.StatusTooManyRequests {
		t.Fatal("canonical-host login was rate-limited after a mismatched-host redirect")
	}
	if rr2.Code != http.StatusFound {
		t.Fatalf("canonical-host login status = %d, want %d", rr2.Code, http.StatusFound)
	}
	if loc := rr2.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.test/authorize") {
		t.Fatalf("canonical-host login Location = %q, want IdP authorize URL", loc)
	}
	if st.flows != 1 {
		t.Fatalf("auth flows created = %d, want 1", st.flows)
	}
}
