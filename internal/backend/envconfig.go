package backend

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
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
	Name      string
	Group     string
	Default   string
	Sensitive bool
	Kind      envKind
}

// EnvVariable is one row of GET /api/settings/environment. Effective is omitted
// (JSON null) for secrets whose raw value must never leave the backend.
type EnvVariable struct {
	Name      string  `json:"name"`
	Group     string  `json:"group"`
	Set       bool    `json:"set"`
	Effective *string `json:"effective"`
	Default   string  `json:"default"`
	Sensitive bool    `json:"sensitive"`
}

// EnvConfigResponse is the GET /api/settings/environment body.
type EnvConfigResponse struct {
	Variables []EnvVariable `json:"variables"`
}

// backendEnvRegistry is the single source of truth for documented backend env
// vars. Scanner-node variables are intentionally absent — the backend never
// sees them.
var backendEnvRegistry = []envSpec{
	{Name: "BACKEND_ADDR", Group: envGroupListen, Default: ":8080", Kind: envKindString},

	{Name: "DATABASE_URL", Group: envGroupDatabase, Sensitive: true, Kind: envKindDSN},
	{Name: "DATABASE_PASSWORD_FILE", Group: envGroupDatabase, Sensitive: true, Kind: envKindPath},

	{Name: "OIDC_ISSUER", Group: envGroupAuth, Kind: envKindString},
	{Name: "AUTH_DISABLED", Group: envGroupAuth, Default: "false", Kind: envKindBoolExactTrue},
	{Name: "OIDC_DISCOVERY_URL", Group: envGroupAuth, Default: "OIDC_ISSUER", Kind: envKindDiscovery},
	{Name: "OIDC_CLIENT_ID", Group: envGroupAuth, Kind: envKindString},
	{Name: "OIDC_CLIENT_SECRET", Group: envGroupAuth, Sensitive: true, Kind: envKindSecret},
	{Name: "APP_BASE_URL", Group: envGroupAuth, Default: "http://localhost:8080", Kind: envKindString},
	{Name: "OIDC_REDIRECT_URL", Group: envGroupAuth, Default: "APP_BASE_URL/api/auth/callback", Kind: envKindRedirectURL},
	{Name: "POST_LOGIN_REDIRECT", Group: envGroupAuth, Default: "APP_BASE_URL/", Kind: envKindPostLogin},
	{Name: "OIDC_SCOPES", Group: envGroupAuth, Default: "openid,profile,email", Kind: envKindString},
	{Name: "OIDC_ROLES_CLAIM", Group: envGroupAuth, Default: "groups", Kind: envKindString},
	{Name: "OIDC_ADMIN_GROUP", Group: envGroupAuth, Default: "admin", Kind: envKindString},
	{Name: "OIDC_OPERATOR_GROUP", Group: envGroupAuth, Default: "operator", Kind: envKindString},
	{Name: "OIDC_VIEWER_GROUP", Group: envGroupAuth, Default: "viewer", Kind: envKindString},
	{Name: "SESSION_TTL", Group: envGroupAuth, Default: "12h", Kind: envKindDuration},
	{Name: "SESSION_COOKIE_NAME", Group: envGroupAuth, Kind: envKindCookieName},
	{Name: "COOKIE_SECURE", Group: envGroupAuth, Default: "true", Kind: envKindBoolNotFalse},
	{Name: "AUTH_MAX_LIVE_FLOWS", Group: envGroupAuth, Default: strconv.Itoa(store.DefaultMaxLiveAuthFlows), Kind: envKindInt},
	{Name: "AUTH_LOGIN_RATE", Group: envGroupAuth, Default: formatFloat(DefaultAuthLoginRate), Kind: envKindFloat},
	{Name: "AUTH_LOGIN_BURST", Group: envGroupAuth, Default: strconv.Itoa(DefaultAuthLoginBurst), Kind: envKindInt},
	{Name: "AUTH_LOGIN_MAX_CLIENTS", Group: envGroupAuth, Default: strconv.Itoa(DefaultAuthLoginMaxClients), Kind: envKindInt},
	{Name: "AUTH_TRUSTED_PROXY_CIDRS", Group: envGroupAuth, Kind: envKindString},

	{Name: "S3_ENDPOINT", Group: envGroupObjectStore, Kind: envKindString},
	{Name: "S3_BUCKET", Group: envGroupObjectStore, Default: "nuclei-raw", Kind: envKindString},
	{Name: "S3_ACCESS_KEY_ID", Group: envGroupObjectStore, Sensitive: true, Kind: envKindSecret},
	{Name: "S3_SECRET_ACCESS_KEY", Group: envGroupObjectStore, Sensitive: true, Kind: envKindSecret},
	{Name: "S3_REGION", Group: envGroupObjectStore, Default: "us-east-1", Kind: envKindString},
	{Name: "S3_USE_SSL", Group: envGroupObjectStore, Default: "true", Kind: envKindBoolNotFalse},

	{Name: "TEMPLATE_SYNC_INTERVAL", Group: envGroupTemplate, Default: "6h", Kind: envKindDuration},
	{Name: "TEMPLATE_SYNC_REPO", Group: envGroupTemplate, Default: defaultTemplateRepo, Kind: envKindTemplateRepo},
	{Name: "TEMPLATE_SYNC_REF", Group: envGroupTemplate, Default: "latest", Kind: envKindString},
	{Name: "TEMPLATE_SYNC_DIR", Group: envGroupTemplate, Default: "/tmp/nsc-template-sync", Kind: envKindPath},
	{Name: "TEMPLATE_DISTRIBUTE_INTERVAL", Group: envGroupTemplate, Default: "1h", Kind: envKindDuration},

	{Name: "RETENTION_SWEEP_INTERVAL", Group: envGroupRetention, Default: "1h", Kind: envKindDuration},

	{Name: "SCANNER_URL", Group: envGroupScannerSeed, Default: "http://localhost:8081", Kind: envKindString},
	{Name: "SCANNER_TOKEN", Group: envGroupScannerSeed, Sensitive: true, Kind: envKindSecret},
	{Name: "SCAN_ZONES", Group: envGroupScannerSeed, Sensitive: true, Kind: envKindZones},
	{Name: "NODE_HEALTH_INTERVAL", Group: envGroupScannerSeed, Default: "30s", Kind: envKindDuration},

	{Name: "EXPORT_SPOOL_DIR", Group: envGroupExport, Kind: envKindPath},
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
		Name:      spec.Name,
		Group:     spec.Group,
		Set:       set,
		Default:   spec.Default,
		Sensitive: spec.Sensitive,
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

// redactDSN strips userinfo (URL username/password) and libpq user/password
// keys so a DSN can be shown without credentials.
func redactDSN(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		u.User = nil
		q := u.Query()
		q.Del("password")
		q.Del("user")
		u.RawQuery = q.Encode()
		return u.String()
	}
	fields := strings.Fields(raw)
	kept := make([]string, 0, len(fields))
	for _, f := range fields {
		key, _, ok := strings.Cut(f, "=")
		if !ok {
			kept = append(kept, f)
			continue
		}
		switch strings.ToLower(key) {
		case "password", "user", "passfile":
			continue
		default:
			kept = append(kept, f)
		}
	}
	return strings.Join(kept, " ")
}
