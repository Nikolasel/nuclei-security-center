package backend

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// Environment-configuration registry (#336). The Settings UI and Configuration.md
// are checked against this allowlist so they cannot drift. Values are resolved
// the same way the running backend consumes them; secrets never leave this
// package as raw env text.

const (
	envGroupListen      = "listen/server"
	envGroupDatabase    = "database"
	envGroupAuth        = "auth/session"
	envGroupObjectStore = "object storage"
	envGroupTemplate    = "template sync/distribution"
	envGroupRetention   = "retention sweeps"
	envGroupScannerSeed = "scanner seeding"
	envGroupExport      = "export scratch"

	defaultTemplateRepo = "https://github.com/projectdiscovery/nuclei-templates.git"
)

type envKind int

const (
	envKindString envKind = iota
	envKindSecret
	envKindPath
	envKindDSN
	envKindZones
	envKindBoolNotFalse
	envKindBoolExactTrue
	envKindDuration
	envKindInt
	envKindFloat
	envKindCookieName
	envKindRedirectURL
	envKindPostLogin
	envKindDiscovery
	envKindTemplateRepo
)

// envSpec is one allowlisted backend environment variable.
type envSpec struct {
	Name        string
	Group       string
	Default     string
	Sensitive   bool
	Kind        envKind
	Description string
}

// EnvVariable is one row of GET /api/settings/environment. Effective is omitted
// (JSON null) for secrets whose raw value must never leave the backend.
type EnvVariable struct {
	Name        string  `json:"name"`
	Group       string  `json:"group"`
	Set         bool    `json:"set"`
	Effective   *string `json:"effective"`
	Default     string  `json:"default"`
	Sensitive   bool    `json:"sensitive"`
	Description string  `json:"description"`
}

// EnvConfigResponse is the GET /api/settings/environment body.
type EnvConfigResponse struct {
	Variables []EnvVariable `json:"variables"`
}

// backendEnvRegistry is the single source of truth for documented backend env
// vars. Scanner-node variables are intentionally absent — the backend never
// sees them.
var backendEnvRegistry = []envSpec{
	{Name: "BACKEND_ADDR", Group: envGroupListen, Default: ":8080", Kind: envKindString, Description: "HTTP listen address."},

	{Name: "DATABASE_URL", Group: envGroupDatabase, Sensitive: true, Kind: envKindDSN, Description: "PostgreSQL DSN. Use TLS in production."},
	{Name: "DATABASE_PASSWORD_FILE", Group: envGroupDatabase, Sensitive: true, Kind: envKindPath, Description: "File containing only the DB password. Re-read before each new connection so credentials can rotate without a restart."},

	{Name: "OIDC_ISSUER", Group: envGroupAuth, Kind: envKindString, Description: "Browser-visible issuer URL. Setting it enables OIDC/BFF auth. Required unless AUTH_DISABLED is true."},
	{Name: "AUTH_DISABLED", Group: envGroupAuth, Default: "false", Kind: envKindBoolExactTrue, Description: "Explicit all-roles development mode when OIDC_ISSUER is unset. Never use in production."},
	{Name: "OIDC_DISCOVERY_URL", Group: envGroupAuth, Default: "OIDC_ISSUER", Kind: envKindDiscovery, Description: "Internal metadata URL when the backend reaches the issuer at a different address."},
	{Name: "OIDC_CLIENT_ID", Group: envGroupAuth, Kind: envKindString, Description: "Confidential client ID. Required with OIDC."},
	{Name: "OIDC_CLIENT_SECRET", Group: envGroupAuth, Sensitive: true, Kind: envKindSecret, Description: "Confidential client secret. Required with OIDC."},
	{Name: "APP_BASE_URL", Group: envGroupAuth, Default: "http://localhost:8080", Kind: envKindString, Description: "Canonical public application URL. Browser login and the SPA redirect onto this origin when Host differs."},
	{Name: "OIDC_REDIRECT_URL", Group: envGroupAuth, Default: "APP_BASE_URL/api/auth/callback", Kind: envKindRedirectURL, Description: "Callback registered with the IdP."},
	{Name: "POST_LOGIN_REDIRECT", Group: envGroupAuth, Default: "APP_BASE_URL/", Kind: envKindPostLogin, Description: "Browser destination after login."},
	{Name: "OIDC_SCOPES", Group: envGroupAuth, Default: "openid,profile,email", Kind: envKindString, Description: "Comma-separated scopes."},
	{Name: "OIDC_ROLES_CLAIM", Group: envGroupAuth, Default: "groups", Kind: envKindString, Description: "ID-token claim containing groups or roles."},
	{Name: "OIDC_ADMIN_GROUP", Group: envGroupAuth, Default: "admin", Kind: envKindString, Description: "Group mapped to NSC admin."},
	{Name: "OIDC_OPERATOR_GROUP", Group: envGroupAuth, Default: "operator", Kind: envKindString, Description: "Group mapped to NSC operator."},
	{Name: "OIDC_VIEWER_GROUP", Group: envGroupAuth, Default: "viewer", Kind: envKindString, Description: "Group mapped to NSC viewer."},
	{Name: "SESSION_TTL", Group: envGroupAuth, Default: "12h", Kind: envKindDuration, Description: "Server-side session lifetime, between 15m and 24h. Longer values are rejected."},
	{Name: "SESSION_COOKIE_NAME", Group: envGroupAuth, Kind: envKindCookieName, Description: "Session cookie name. Secure deployments use the Host- prefix."},
	{Name: "COOKIE_SECURE", Group: envGroupAuth, Default: "true", Kind: envKindBoolNotFalse, Description: "Secure-cookie flag. Set false only for local plaintext HTTP."},
	{Name: "AUTH_MAX_LIVE_FLOWS", Group: envGroupAuth, Default: strconv.Itoa(store.DefaultMaxLiveAuthFlows), Kind: envKindInt, Description: "Global active browser-flow cap across backend replicas. At the cap, new flows fail closed with 429."},
	{Name: "AUTH_LOGIN_RATE", Group: envGroupAuth, Default: formatFloat(DefaultAuthLoginRate), Kind: envKindFloat, Description: "Per-peer login-flow token refill rate in requests per second."},
	{Name: "AUTH_LOGIN_BURST", Group: envGroupAuth, Default: strconv.Itoa(DefaultAuthLoginBurst), Kind: envKindInt, Description: "Per-peer login burst."},
	{Name: "AUTH_LOGIN_MAX_CLIENTS", Group: envGroupAuth, Default: strconv.Itoa(DefaultAuthLoginMaxClients), Kind: envKindInt, Description: "Maximum in-memory peer limiters; the stalest entry is evicted at capacity."},
	{Name: "AUTH_TRUSTED_PROXY_CIDRS", Group: envGroupAuth, Kind: envKindString, Description: "Comma-separated trusted proxy CIDRs (maximum 64). Only matching direct peers may supply sanitized X-Forwarded-For client addresses."},

	{Name: "S3_ENDPOINT", Group: envGroupObjectStore, Kind: envKindString, Description: "S3-compatible endpoint as host:port, without a scheme. Unset disables archiving."},
	{Name: "S3_BUCKET", Group: envGroupObjectStore, Default: "nuclei-raw", Kind: envKindString, Description: "Archive bucket; created at startup when absent."},
	{Name: "S3_ACCESS_KEY_ID", Group: envGroupObjectStore, Sensitive: true, Kind: envKindSecret, Description: "Static access key. Leave empty to use the ambient AWS credential chain."},
	{Name: "S3_SECRET_ACCESS_KEY", Group: envGroupObjectStore, Sensitive: true, Kind: envKindSecret, Description: "Static secret key."},
	{Name: "S3_REGION", Group: envGroupObjectStore, Default: "us-east-1", Kind: envKindString, Description: "S3 region. Must match the store's configured region."},
	{Name: "S3_USE_SSL", Group: envGroupObjectStore, Default: "true", Kind: envKindBoolNotFalse, Description: "TLS for the S3 endpoint. Set false only for local plaintext HTTP."},

	{Name: "TEMPLATE_SYNC_INTERVAL", Group: envGroupTemplate, Default: "6h", Kind: envKindDuration, Description: "Upstream catalog refresh cadence."},
	{Name: "TEMPLATE_SYNC_REPO", Group: envGroupTemplate, Default: defaultTemplateRepo, Kind: envKindTemplateRepo, Description: "Upstream catalog Git repository. Set to an explicit empty value to disable upstream sync while retaining custom templates and distribution."},
	{Name: "TEMPLATE_SYNC_REF", Group: envGroupTemplate, Default: "latest", Kind: envKindString, Description: "Revision to mirror. latest is the highest stable tag; tags and SHAs are reproducible, branches advance."},
	{Name: "TEMPLATE_SYNC_DIR", Group: envGroupTemplate, Default: "/tmp/nsc-template-sync", Kind: envKindPath, Description: "Backend clone cache. Mount persistent storage to avoid repeated full clones."},
	{Name: "TEMPLATE_DISTRIBUTE_INTERVAL", Group: envGroupTemplate, Default: "1h", Kind: envKindDuration, Description: "How often stale, idle scanner nodes receive the current full catalog bundle. Pre-dispatch top-up still runs."},

	{Name: "RETENTION_SWEEP_INTERVAL", Group: envGroupRetention, Default: "1h", Kind: envKindDuration, Description: "How often the backend applies the DB-backed scan-retention policy."},

	{Name: "SCANNER_URL", Group: envGroupScannerSeed, Default: "http://localhost:8081", Kind: envKindString, Description: "Endpoint used to seed the first catch-all scanner node. Seed-only after first boot."},
	{Name: "SCANNER_TOKEN", Group: envGroupScannerSeed, Sensitive: true, Kind: envKindSecret, Description: "Token used with SCANNER_URL to seed the default node. At least 32 characters on the scanner."},
	{Name: "SCAN_ZONES", Group: envGroupScannerSeed, Sensitive: true, Kind: envKindZones, Description: "JSON array of additional seed nodes. Seed-only; PostgreSQL is authoritative afterward."},
	{Name: "NODE_HEALTH_INTERVAL", Group: envGroupScannerSeed, Default: "30s", Kind: envKindDuration, Description: "Capability-poll interval. A node stays healthy for three times this interval after its last successful poll."},

	{Name: "EXPORT_SPOOL_DIR", Group: envGroupExport, Kind: envKindPath, Description: "Writable scratch directory for findings exports and scan-bundle imports."},
}

func resolveEnvConfig() []EnvVariable {
	out := make([]EnvVariable, 0, len(backendEnvRegistry))
	for _, spec := range backendEnvRegistry {
		out = append(out, resolveEnvSpec(spec))
	}
	return out
}

func resolveEnvSpec(spec envSpec) EnvVariable {
	raw, set := os.LookupEnv(spec.Name)
	row := EnvVariable{
		Name:        spec.Name,
		Group:       spec.Group,
		Set:         set,
		Default:     spec.Default,
		Sensitive:   spec.Sensitive,
		Description: spec.Description,
	}
	switch spec.Kind {
	case envKindSecret:
		return row
	case envKindPath:
		if spec.Name == "EXPORT_SPOOL_DIR" {
			row.Default = os.TempDir()
		}
		if !set || raw == "" {
			row.Effective = strPtr(row.Default)
			return row
		}
		row.Effective = strPtr(raw)
		return row
	case envKindDSN:
		if !set || raw == "" {
			return row
		}
		row.Effective = strPtr(redactDSN(raw))
		return row
	case envKindZones:
		row.Default = ""
		if !set || strings.TrimSpace(raw) == "" {
			row.Effective = strPtr("0 seed nodes")
			return row
		}
		row.Effective = strPtr(fmt.Sprintf("%d seed nodes", scanZoneCount(raw)))
		return row
	case envKindBoolNotFalse:
		row.Effective = strPtr(strconv.FormatBool(raw != "false"))
		return row
	case envKindBoolExactTrue:
		row.Effective = strPtr(strconv.FormatBool(raw == "true"))
		return row
	case envKindDuration:
		row.Effective = strPtr(effectiveDuration(raw, spec.Default))
		return row
	case envKindInt:
		row.Effective = strPtr(strconv.Itoa(effectiveInt(raw, spec.Default)))
		return row
	case envKindFloat:
		row.Effective = strPtr(formatFloat(effectiveFloat(raw, spec.Default)))
		return row
	case envKindCookieName:
		secure := os.Getenv("COOKIE_SECURE") != "false"
		def := sessionCookieName("", secure)
		row.Default = def
		configured := strings.TrimSpace(raw)
		row.Effective = strPtr(sessionCookieName(configured, secure))
		return row
	case envKindRedirectURL:
		base := envOrLookup("APP_BASE_URL", "http://localhost:8080")
		def := base + "/api/auth/callback"
		if !set || raw == "" {
			row.Effective = strPtr(def)
			return row
		}
		row.Effective = strPtr(raw)
		return row
	case envKindPostLogin:
		base := envOrLookup("APP_BASE_URL", "http://localhost:8080")
		def := base + "/"
		if !set || raw == "" {
			row.Effective = strPtr(def)
			return row
		}
		row.Effective = strPtr(raw)
		return row
	case envKindDiscovery:
		issuer := os.Getenv("OIDC_ISSUER")
		if !set || raw == "" {
			row.Effective = strPtr(issuer)
			return row
		}
		row.Effective = strPtr(raw)
		return row
	case envKindTemplateRepo:
		if !set {
			row.Effective = strPtr(defaultTemplateRepo)
			return row
		}
		row.Effective = strPtr(raw)
		return row
	default:
		if !set || raw == "" {
			row.Effective = strPtr(spec.Default)
			return row
		}
		row.Effective = strPtr(raw)
		return row
	}
}

func envOrLookup(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func strPtr(s string) *string { return &s }

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func effectiveDuration(raw, def string) string {
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return def
	}
	return raw
}

func effectiveInt(raw, def string) int {
	fallback, _ := strconv.Atoi(def)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func effectiveFloat(raw, def string) float64 {
	fallback, _ := strconv.ParseFloat(def, 64)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return v
}

func scanZoneCount(raw string) int {
	raw = strings.TrimSpace(raw)
	var zones []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &zones); err != nil {
		return 0
	}
	return len(zones)
}

const redactedUnparseableDSN = "(unparseable, hidden)"

// redactDSN rebuilds a credential-free DSN from a parsed pgx config so quoting,
// spaces around '=', and malformed URLs cannot leak a password. Parse failures
// return a fixed placeholder — never the raw value.
func redactDSN(raw string) string {
	cfg, err := pgconn.ParseConfig(raw)
	if err != nil {
		return redactedUnparseableDSN
	}
	parts := make([]string, 0, 4+len(cfg.RuntimeParams))
	if cfg.Host != "" {
		parts = append(parts, "host="+cfg.Host)
	}
	if cfg.Port != 0 {
		parts = append(parts, fmt.Sprintf("port=%d", cfg.Port))
	}
	if cfg.Database != "" {
		parts = append(parts, "dbname="+cfg.Database)
	}
	if cfg.ConnectTimeout > 0 {
		parts = append(parts, fmt.Sprintf("connect_timeout=%d", int(cfg.ConnectTimeout.Seconds())))
	}
	if cfg.SSLNegotiation != "" {
		parts = append(parts, "sslnegotiation="+cfg.SSLNegotiation)
	}
	keys := make([]string, 0, len(cfg.RuntimeParams))
	for k := range cfg.RuntimeParams {
		switch strings.ToLower(k) {
		case "password", "user", "passfile", "sslpassword":
			continue
		default:
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+cfg.RuntimeParams[k])
	}
	if len(parts) == 0 {
		return redactedUnparseableDSN
	}
	return strings.Join(parts, " ")
}
