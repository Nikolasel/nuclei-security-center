package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

var backendEnvDocName = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

const (
	canaryScannerToken = "nsc-canary-scanner-token-7e13ecd1"
	canaryOIDCSecret   = "nsc-canary-oidc-secret-7e13ecd1"
	canaryS3Access     = "nsc-canary-s3-access-7e13ecd1"
	canaryS3Secret     = "nsc-canary-s3-secret-7e13ecd1"
	canaryDBPassword   = "nsc-canary-db-password-7e13ecd1"
	canaryFileSecret   = "nsc-canary-db-file-secret-7e13ecd1"
	canaryZoneToken    = "nsc-canary-zone-token-7e13ecd1"
	canaryZoneKey      = "nsc-canary-zone-tls-key-7e13ecd1"
	canarySMTPPassword = "nsc-canary-smtp-password-7e13ecd1"
	canarySMTPFile     = "nsc-canary-smtp-file-secret-7e13ecd1"
)

func TestGetEnvironmentRedactsPlantedSecrets(t *testing.T) {
	pwFile := filepath.Join(t.TempDir(), "db.pw")
	if err := os.WriteFile(pwFile, []byte(canaryFileSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", "postgres://nsc:"+canaryDBPassword+"@db.internal:5432/nuclei")
	t.Setenv("DATABASE_PASSWORD_FILE", pwFile)
	t.Setenv("SCANNER_TOKEN", canaryScannerToken)
	t.Setenv("OIDC_CLIENT_SECRET", canaryOIDCSecret)
	t.Setenv("S3_ACCESS_KEY_ID", canaryS3Access)
	t.Setenv("S3_SECRET_ACCESS_KEY", canaryS3Secret)
	t.Setenv("SCAN_ZONES", `[{"name":"dmz","url":"https://scanner-dmz:8081","token":"`+canaryZoneToken+`","cidrs":["10.20.0.0/16"],"tls_client_key":"`+canaryZoneKey+`"}]`)
	smtpFile := filepath.Join(t.TempDir(), "smtp.pw")
	if err := os.WriteFile(smtpFile, []byte(canarySMTPFile+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SMTP_PASSWORD", canarySMTPPassword)
	t.Setenv("SMTP_PASSWORD_FILE", smtpFile)

	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rr := httptest.NewRecorder()
	s.handleGetEnvironment(rr, httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, secret := range []string{
		canaryScannerToken, canaryOIDCSecret, canaryS3Access, canaryS3Secret,
		canaryDBPassword, canaryFileSecret, canaryZoneToken, canaryZoneKey,
		canarySMTPPassword, canarySMTPFile, "nsc:",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("response leaked %q: %s", secret, body)
		}
	}

	var got EnvConfigResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byName := map[string]EnvVariable{}
	for _, v := range got.Variables {
		byName[v.Name] = v
	}
	if v := byName["DATABASE_URL"]; v.Effective == nil || strings.Contains(*v.Effective, canaryDBPassword) {
		t.Errorf("DATABASE_URL effective = %v", v.Effective)
	} else if !strings.Contains(*v.Effective, "db.internal") {
		t.Errorf("DATABASE_URL effective %q missing host", *v.Effective)
	}
	if v := byName["DATABASE_PASSWORD_FILE"]; v.Effective == nil || *v.Effective != pwFile {
		t.Errorf("DATABASE_PASSWORD_FILE effective = %v, want path %q", v.Effective, pwFile)
	}
	if v := byName["SMTP_PASSWORD_FILE"]; v.Effective == nil || *v.Effective != smtpFile {
		t.Errorf("SMTP_PASSWORD_FILE effective = %v, want path %q", v.Effective, smtpFile)
	}
	if v := byName["SCAN_ZONES"]; v.Effective == nil || *v.Effective != "1 seed nodes" {
		t.Errorf("SCAN_ZONES effective = %v, want 1 seed nodes", v.Effective)
	}
	for _, name := range []string{"SCANNER_TOKEN", "OIDC_CLIENT_SECRET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "SMTP_PASSWORD"} {
		if v := byName[name]; !v.Set || v.Effective != nil {
			t.Errorf("%s set=%v effective=%v, want set with null effective", name, v.Set, v.Effective)
		}
	}
}

func TestGetEnvironmentRequiresAdmin(t *testing.T) {
	s := &Server{
		auth: &Authenticator{cfg: AuthConfig{CookieName: "nsc_session"}},
		log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handlerFor := func(roles ...string) http.HandlerFunc {
		return s.requireAuthWithResolvers(
			func(context.Context, string) (store.Identity, error) {
				return store.Identity{}, store.ErrNotFound
			},
			func(*http.Request) (store.Identity, error) {
				return store.Identity{Subject: "tester", Roles: roles}, nil
			},
			func(w http.ResponseWriter, r *http.Request) {
				if !satisfies(identityFrom(r.Context()), RoleAdmin) {
					http.Error(w, "insufficient role", http.StatusForbidden)
					return
				}
				s.handleGetEnvironment(w, r)
			},
		)
	}

	for _, role := range []string{RoleViewer, RoleOperator} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil)
		handlerFor(role)(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("role %s: status = %d, want 403 body %q", role, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), `"variables"`) {
			t.Errorf("role %s: leaked environment payload: %s", role, rr.Body.String())
		}
	}

	rr := httptest.NewRecorder()
	handlerFor(RoleAdmin)(rr, httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("admin: status = %d, body = %s", rr.Code, rr.Body.String())
	}

	// Route registration: auth-enabled server, no cookie → 401.
	srv := NewServer(nil, nil, &Authenticator{cfg: AuthConfig{CookieName: "nsc_session"}}, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}
}

func TestResolveEnvConfigParsesEffectiveValues(t *testing.T) {
	t.Setenv("BACKEND_ADDR", ":9999")
	t.Setenv("COOKIE_SECURE", "false")
	t.Setenv("AUTH_DISABLED", "true")
	t.Setenv("NODE_HEALTH_INTERVAL", "15s")
	t.Setenv("AUTH_LOGIN_RATE", "2.5")
	t.Setenv("TEMPLATE_SYNC_REPO", "")
	t.Setenv("S3_USE_SSL", "false")
	t.Setenv("SESSION_TTL", "45m")
	t.Setenv("SMTP_HOST", "mail.internal")
	t.Setenv("SMTP_PORT", "465")
	t.Setenv("SMTP_STARTTLS", "false")
	t.Setenv("SMTP_TLS", "true")

	byName := map[string]EnvVariable{}
	for _, v := range resolveEnvConfig() {
		byName[v.Name] = v
	}
	assertEff := func(name, want string) {
		t.Helper()
		v := byName[name]
		if v.Effective == nil || *v.Effective != want {
			t.Errorf("%s effective = %v, want %q (set=%v)", name, v.Effective, want, v.Set)
		}
	}
	assertEff("BACKEND_ADDR", ":9999")
	assertEff("COOKIE_SECURE", "false")
	assertEff("AUTH_DISABLED", "true")
	assertEff("NODE_HEALTH_INTERVAL", "15s")
	assertEff("AUTH_LOGIN_RATE", "2.5")
	assertEff("TEMPLATE_SYNC_REPO", "")
	assertEff("S3_USE_SSL", "false")
	assertEff("SESSION_TTL", "45m")
	assertEff("SESSION_COOKIE_NAME", "nsc_session")
	assertEff("SMTP_HOST", "mail.internal")
	assertEff("SMTP_PORT", "465")
	assertEff("SMTP_STARTTLS", "false")
	assertEff("SMTP_TLS", "true")
	if !byName["TEMPLATE_SYNC_REPO"].Set {
		t.Error("TEMPLATE_SYNC_REPO should be set (explicit empty)")
	}
	if byName["BACKEND_ADDR"].Description == "" {
		t.Error("BACKEND_ADDR description missing from API payload")
	}
}

func TestEffectiveTCPPortRejectsOutOfRange(t *testing.T) {
	t.Setenv("SMTP_PORT", "70000")
	for _, v := range resolveEnvConfig() {
		if v.Name != "SMTP_PORT" {
			continue
		}
		if v.Effective == nil || *v.Effective != "587" {
			t.Fatalf("SMTP_PORT effective = %v, want 587 (out of range rejected)", v.Effective)
		}
		return
	}
	t.Fatal("SMTP_PORT missing from registry")
}

func TestBackendEnvRegistryMatchesConfigurationDocs(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	docPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "docs", "admin", "Configuration.md")
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	backendSection, _, _ := strings.Cut(string(raw), "\n## Scanner\n")
	documented := parseBackendEnvDocTable(t, backendSection)
	registered := map[string]envSpec{}
	for _, spec := range backendEnvRegistry {
		if _, dup := registered[spec.Name]; dup {
			t.Errorf("duplicate registry entry %s", spec.Name)
		}
		registered[spec.Name] = spec
		if spec.Description == "" {
			t.Errorf("registry variable %s has empty Description", spec.Name)
		}
		if strings.Contains(spec.Description, "`") || strings.Contains(spec.Description, "](") {
			t.Errorf("registry variable %s Description must be plain (no backticks or markdown links): %q", spec.Name, spec.Description)
		}
		purpose, ok := documented[spec.Name]
		if !ok {
			t.Errorf("registry variable %s missing from Configuration.md backend tables", spec.Name)
			continue
		}
		if purpose != spec.Description {
			t.Errorf("%s Description drifted from Configuration.md Purpose\n  registry: %q\n  docs:     %q", spec.Name, spec.Description, purpose)
		}
	}
	for name := range documented {
		if _, ok := registered[name]; !ok {
			t.Errorf("Configuration.md documents %s but it is not in backendEnvRegistry", name)
		}
	}
}

func parseBackendEnvDocTable(t *testing.T, backendSection string) map[string]string {
	t.Helper()
	documented := map[string]string{}
	for _, line := range strings.Split(backendSection, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := markdownTableCells(line)
		if len(cells) < 3 {
			continue
		}
		name := strings.Trim(cells[0], "`")
		if !backendEnvDocName.MatchString(name) {
			continue
		}
		purpose := strings.TrimSpace(cells[len(cells)-1])
		if purpose == "" || purpose == "Purpose" {
			continue
		}
		if _, dup := documented[name]; dup {
			t.Errorf("Configuration.md documents %s twice", name)
		}
		documented[name] = purpose
	}
	return documented
}

func markdownTableCells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func TestRedactDSN(t *testing.T) {
	cases := []struct {
		name         string
		raw          string
		leaks        []string
		wantContains []string
		wantHidden   bool
	}{
		{
			name:         "url userinfo",
			raw:          "postgres://alice:s3cret@db.example:5432/nsc?sslmode=require",
			leaks:        []string{"s3cret", "alice"},
			wantContains: []string{"db.example", "nsc"},
		},
		{
			name:         "keyword value",
			raw:          "host=db.example user=alice password=s3cret dbname=nsc",
			leaks:        []string{"s3cret", "alice", "user=", "password="},
			wantContains: []string{"db.example", "nsc"},
		},
		{
			name:  "quoted password with space",
			raw:   "host=db user=a password='my secret' dbname=x",
			leaks: []string{"secret", "password="},
		},
		{
			name:  "spaces around equals",
			raw:   "host=db password = abc",
			leaks: []string{"abc", "password="},
		},
		{
			name:       "invalid percent-escape userinfo",
			raw:        "postgres://nsc:pa%ss@h/db",
			leaks:      []string{"pa%ss", "nsc"},
			wantHidden: true,
		},
		{
			name:  "sslpassword",
			raw:   "host=db sslpassword=sslpw dbname=x",
			leaks: []string{"sslpw", "sslpassword="},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactDSN(tc.raw)
			if tc.wantHidden && got != redactedUnparseableDSN {
				t.Fatalf("got %q, want %q", got, redactedUnparseableDSN)
			}
			for _, leak := range tc.leaks {
				if strings.Contains(got, leak) {
					t.Fatalf("leaked %q in %q", leak, got)
				}
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q in %q", want, got)
				}
			}
		})
	}
}

func TestGetEnvironmentDoesNotDumpProcessEnviron(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "nsc-canary-k8s-host-7e13ecd1")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "nsc-canary-aws-secret-7e13ecd1")
	s := &Server{log: slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))}
	rr := httptest.NewRecorder()
	s.handleGetEnvironment(rr, httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil))
	body := rr.Body.String()
	if strings.Contains(body, "KUBERNETES_SERVICE_HOST") || strings.Contains(body, "nsc-canary-k8s-host-7e13ecd1") {
		t.Fatal("dumped unrelated platform env")
	}
	if strings.Contains(body, "AWS_SECRET_ACCESS_KEY") || strings.Contains(body, "nsc-canary-aws-secret-7e13ecd1") {
		t.Fatal("dumped unrelated cloud secret")
	}
}
