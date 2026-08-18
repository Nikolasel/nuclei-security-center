// Command backend is the system of record and orchestrator. It owns Postgres,
// dispatches scans to a scanner node, polls to completion, and ingests findings.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/backend"
	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/web"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	addr := envOr("BACKEND_ADDR", ":8080")
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Error("DATABASE_URL is required")
		os.Exit(1)
	}
	scannerURL := envOr("SCANNER_URL", "http://localhost:8081")
	scannerToken := os.Getenv("SCANNER_TOKEN")
	if scannerToken == "" {
		log.Error("SCANNER_TOKEN is required")
		os.Exit(1)
	}

	storeOpts, err := storeOptionsFromEnv()
	if err != nil {
		log.Error("configure store", "err", err)
		os.Exit(1)
	}
	loginRate, loginBurst, loginMaxClients, err := authLoginAdmissionFromEnv()
	if err != nil {
		log.Error("configure auth admission", "err", err)
		os.Exit(1)
	}
	trustedProxyCIDRs, err := trustedProxyCIDRsFromEnv()
	if err != nil {
		log.Error("configure trusted proxy boundary", "err", err)
		os.Exit(1)
	}
	loginSettings := authLoginAdmissionSettings{
		rate:              loginRate,
		burst:             loginBurst,
		maxClients:        loginMaxClients,
		trustedProxyCIDRs: trustedProxyCIDRs,
	}

	ctx := context.Background()
	st, err := openStoreWithRetry(ctx, dsn, storeOpts, log)
	if err != nil {
		log.Error("connect store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	log.Info("acquiring migration lock and applying migrations")
	if err := st.Migrate(ctx); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	}
	log.Info("migrations applied")

	if n, err := st.FailOrphanedScans(ctx, "orphaned: backend restarted while scan was in progress"); err != nil {
		log.Error("reconcile orphaned scans", "err", err)
	} else if n > 0 {
		log.Warn("reconciled orphaned scans", "count", n)
	}

	archive, err := buildObjectStore(ctx, log)
	if err != nil {
		log.Error("configure object storage", "err", err)
		os.Exit(1)
	}

	// Scanner node registry (#22): the DB is the system of record. Config
	// (SCANNER_URL as the default catch-all node + optional SCAN_ZONES) only seeds
	// the table on first boot; thereafter the admin manages nodes via the API/UI.
	if err := backend.SeedScannerNodes(ctx, st, scannerURL, scannerToken, os.Getenv("SCAN_ZONES"), log); err != nil {
		log.Error("seed scanner nodes", "err", err)
		os.Exit(1)
	}

	// Node health (#98): poll each registered node's /v1/capabilities to derive
	// liveness (strictly backend→node). Dispatch fails fast to a known-unhealthy
	// node instead of a black hole.
	health := backend.NewHealthMonitor(st, nodeHealthInterval(), log)
	health.Start(ctx)

	orch := backend.NewOrchestrator(st, archive, health, log)

	auth, err := buildAuthenticator(ctx, st, log, loginSettings)
	if err != nil {
		log.Error("configure auth", "err", err)
		os.Exit(1)
	}
	if auth != nil {
		startSessionSweeper(ctx, st, log)
	} else {
		log.Warn("OIDC_ISSUER not set — authentication is DISABLED (dev mode); all requests act as an all-roles dev user")
	}

	apiSrv := backend.NewServer(st, orch, auth, archive, web.Handler(), log)
	// Template catalog sync (#85) mirrors nuclei-templates into Postgres. Like
	// S3_ENDPOINT / OIDC_ISSUER, an empty TEMPLATE_SYNC_REPO disables the feature
	// (a full clone is ~1 GB of .git and pointless in a headless dev stack).
	if cfg := templateSyncConfig(); cfg.Repo == "" {
		log.Warn("TEMPLATE_SYNC_REPO empty — upstream template catalog sync is DISABLED")
	} else {
		templateSyncer, err := backend.NewTemplateSyncer(st, cfg, log)
		if err != nil {
			log.Error("configure template sync", "err", err)
			os.Exit(1)
		}
		apiSrv.SetTemplateSyncer(templateSyncer)
		templateSyncer.Start(ctx)
		log.Info("template syncer started", "repo", cfg.Repo, "ref", cfg.Ref, "dir", cfg.Dir)

	}
	// Template distribution (#85) also serves custom-only catalogs when upstream
	// sync is disabled: hourly idle pushes, admin "sync now", and the mandatory
	// pre-dispatch top-up all use the same distributor.
	distributor := backend.NewTemplateDistributor(st, health, templateDistributeInterval(), log)
	distributor.Start(ctx)
	apiSrv.SetTemplateDistributor(distributor)
	log.Info("template distributor started")

	// The scheduler ticker dispatches cron schedules; the DB is its source of
	// truth so it resumes cleanly across restarts.
	backend.NewScheduler(st, apiSrv, log).Start(ctx)
	log.Info("scheduler started")

	// The retention sweeper (#95) deletes scans older than the admin-configured
	// window. It reads the policy fresh each tick (no-op until an admin enables
	// it), so it's always safe to start.
	backend.NewRetentionSweeper(st, archive, retentionSweepInterval(), log).Start(ctx)
	log.Info("retention sweeper started")

	srv := &http.Server{
		Addr:              addr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("backend listening", "addr", addr, "scanner", scannerURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	waitForShutdown(log, srv)
}

type authLoginAdmissionSettings struct {
	rate              float64
	burst             int
	maxClients        int
	trustedProxyCIDRs []netip.Prefix
}

// buildAuthenticator wires the OIDC/BFF authenticator from the environment.
// Auth is fail-closed: an unset OIDC_ISSUER is a hard error unless dev mode is
// explicitly opted into with AUTH_DISABLED=true (in which case it returns
// (nil, nil)). When the issuer is set, the remaining required OIDC vars must be
// present.
func buildAuthenticator(ctx context.Context, st *store.Store, log *slog.Logger, loginSettings authLoginAdmissionSettings) (*backend.Authenticator, error) {
	issuer := os.Getenv("OIDC_ISSUER")
	if issuer == "" {
		if os.Getenv("AUTH_DISABLED") != "true" {
			return nil, errors.New("OIDC_ISSUER is required; set AUTH_DISABLED=true to explicitly run without authentication (dev only)")
		}
		return nil, nil
	}

	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required when OIDC_ISSUER is set")
	}
	baseURL := envOr("APP_BASE_URL", "http://localhost:8080")
	redirect := envOr("OIDC_REDIRECT_URL", baseURL+"/api/auth/callback")
	postLogin := envOr("POST_LOGIN_REDIRECT", baseURL+"/")

	ttl := 12 * time.Hour
	if v := os.Getenv("SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, errors.New("SESSION_TTL: " + err.Error())
		}
		ttl = d
	}

	cfg := backend.AuthConfig{
		Issuer:       issuer,
		DiscoveryURL: os.Getenv("OIDC_DISCOVERY_URL"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirect,
		PostLogin:    postLogin,
		Scopes:       splitCSV(envOr("OIDC_SCOPES", "openid,profile,email")),
		RolesClaim:   envOr("OIDC_ROLES_CLAIM", "groups"),
		GroupRoles: map[string]string{
			envOr("OIDC_ADMIN_GROUP", "admin"):       backend.RoleAdmin,
			envOr("OIDC_OPERATOR_GROUP", "operator"): backend.RoleOperator,
			envOr("OIDC_VIEWER_GROUP", "viewer"):     backend.RoleViewer,
		},
		SessionTTL:        ttl,
		CookieName:        envOr("SESSION_COOKIE_NAME", "nsc_session"),
		SecureCookie:      secureCookieEnabled(),
		LoginRate:         loginSettings.rate,
		LoginBurst:        loginSettings.burst,
		LoginMaxClients:   loginSettings.maxClients,
		TrustedProxyCIDRs: loginSettings.trustedProxyCIDRs,
	}

	auth, err := backend.NewAuthenticator(ctx, st, log, cfg)
	if err != nil {
		return nil, err
	}
	if !cfg.SecureCookie {
		log.Warn("COOKIE_SECURE=false — the session cookie will lack the Secure attribute and can be sent over plaintext HTTP; use only in local dev")
	}
	log.Info("OIDC auth enabled", "issuer", issuer, "client_id", clientID)
	return auth, nil
}

func storeOptionsFromEnv() (store.Options, error) {
	maxLive, err := intEnv("AUTH_MAX_LIVE_FLOWS", store.DefaultMaxLiveAuthFlows, 1, store.MaxConfiguredLiveAuthFlows)
	if err != nil {
		return store.Options{}, err
	}
	return store.Options{
		PasswordFile:     os.Getenv("DATABASE_PASSWORD_FILE"),
		MaxLiveAuthFlows: maxLive,
	}, nil
}

func authLoginAdmissionFromEnv() (float64, int, int, error) {
	rateLimit, err := floatEnv("AUTH_LOGIN_RATE", backend.DefaultAuthLoginRate, 0.000001, backend.MaxConfiguredAuthLoginRate)
	if err != nil {
		return 0, 0, 0, err
	}
	burst, err := intEnv("AUTH_LOGIN_BURST", backend.DefaultAuthLoginBurst, 1, backend.MaxConfiguredAuthLoginBurst)
	if err != nil {
		return 0, 0, 0, err
	}
	maxClients, err := intEnv("AUTH_LOGIN_MAX_CLIENTS", backend.DefaultAuthLoginMaxClients, 1, backend.MaxConfiguredAuthLoginClients)
	if err != nil {
		return 0, 0, 0, err
	}
	return rateLimit, burst, maxClients, nil
}

func trustedProxyCIDRsFromEnv() ([]netip.Prefix, error) {
	raw := strings.TrimSpace(os.Getenv("AUTH_TRUSTED_PROXY_CIDRS"))
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > backend.MaxTrustedProxyCIDRs {
		return nil, fmt.Errorf("AUTH_TRUSTED_PROXY_CIDRS contains too many entries")
	}
	seen := make(map[netip.Prefix]struct{}, len(parts))
	prefixes := make([]netip.Prefix, 0, len(parts))
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("AUTH_TRUSTED_PROXY_CIDRS entry %d is empty", index+1)
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("AUTH_TRUSTED_PROXY_CIDRS entry %d: parse prefix: %w", index+1, err)
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func intEnv(name string, defaultValue, minValue, maxValue int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: parse integer: %w", name, err)
	}
	if value < minValue || value > maxValue {
		return 0, fmt.Errorf("%s must be between %d and %d (got %d)", name, minValue, maxValue, value)
	}
	return value, nil
}

func floatEnv(name string, defaultValue, minValue, maxValue float64) (float64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: parse number: %w", name, err)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || value < minValue || value > maxValue {
		return 0, fmt.Errorf("%s must be between %s and %s (got %s)", name,
			strconv.FormatFloat(minValue, 'f', -1, 64),
			strconv.FormatFloat(maxValue, 'f', -1, 64),
			strconv.FormatFloat(value, 'g', -1, 64))
	}
	return value, nil
}

// secureCookieEnabled defaults the session-cookie Secure flag to true, so a TLS
// deployment is secure even if the flag is forgotten. It is disabled only by an
// explicit COOKIE_SECURE=false (mirroring the AUTH_DISABLED dev opt-out).
func secureCookieEnabled() bool {
	return os.Getenv("COOKIE_SECURE") != "false"
}

// buildObjectStore wires the S3-compatible archive from the environment. If
// S3_ENDPOINT is unset it returns (nil, nil) — archiving is disabled and scans
// still ingest normally (dev mode). When set, the bucket is created if absent.
func buildObjectStore(ctx context.Context, log *slog.Logger) (backend.ObjectStore, error) {
	endpoint := os.Getenv("S3_ENDPOINT")
	if endpoint == "" {
		log.Warn("S3_ENDPOINT not set — raw-output archiving is DISABLED")
		return nil, nil
	}
	cfg := backend.ObjectStoreConfig{
		Endpoint:  endpoint,
		Bucket:    envOr("S3_BUCKET", "nuclei-raw"),
		AccessKey: os.Getenv("S3_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("S3_SECRET_ACCESS_KEY"),
		Region:    envOr("S3_REGION", "us-east-1"),
		UseSSL:    os.Getenv("S3_USE_SSL") == "true",
	}
	store, err := backend.NewObjectStore(ctx, cfg)
	if err != nil {
		return nil, err
	}
	log.Info("object storage enabled", "endpoint", endpoint, "bucket", cfg.Bucket)
	return store, nil
}

// startSessionSweeper periodically deletes expired sessions and auth flows.
func startSessionSweeper(ctx context.Context, st *store.Store, log *slog.Logger) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := st.SweepExpiredAuth(ctx); err != nil {
					log.Warn("sweep expired auth", "err", err)
				}
			}
		}
	}()
}

// splitCSV splits a comma-separated env value, trimming spaces and dropping empties.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// openStoreWithRetry tolerates Postgres not being ready yet (compose startup).
func openStoreWithRetry(ctx context.Context, dsn string, opts store.Options, log *slog.Logger) (*store.Store, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		st, err := store.OpenWithOptions(ctx, dsn, opts)
		if err == nil {
			return st, nil
		}
		lastErr = err
		log.Info("waiting for postgres", "attempt", i+1)
		time.Sleep(2 * time.Second)
	}
	return nil, lastErr
}

func waitForShutdown(log *slog.Logger, srv *http.Server) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// nodeHealthInterval is how often the backend polls each scanner node's
// capabilities for liveness (#98). Defaults to 30s; a node is considered healthy
// for 3× this after its last successful poll.
func nodeHealthInterval() time.Duration {
	if v := os.Getenv("NODE_HEALTH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 30 * time.Second
}

// retentionSweepInterval is how often the retention sweeper (#95) checks for
// scans past the retention window. Defaults to hourly (this isn't cron-precision
// work); RETENTION_SWEEP_INTERVAL overrides it (a short value is handy in tests).
func retentionSweepInterval() time.Duration {
	if v := os.Getenv("RETENTION_SWEEP_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// defaultTemplateRepo is the community nuclei-templates catalog mirrored when
// TEMPLATE_SYNC_REPO is unset (zero-config deployment).
const defaultTemplateRepo = "https://github.com/projectdiscovery/nuclei-templates.git"

// templateDistributeInterval is how often the backend pushes the template
// catalog to scanner nodes (#85). Defaults to hourly; only stale, idle nodes are
// pushed to, so a quiet tick is cheap.
func templateDistributeInterval() time.Duration {
	if v := os.Getenv("TEMPLATE_DISTRIBUTE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// templateSyncConfig is deliberately backend-only: scanner nodes receive a
// resolved, immutable bundle in a later #85 slice and never clone upstream
// repositories themselves. "latest" resolves to the highest stable semver tag.
// The repo defaults to the community catalog (zero-config deployment), but an
// explicitly empty TEMPLATE_SYNC_REPO disables sync — hence LookupEnv, so an
// empty value is honored rather than falling back to the default.
func templateSyncConfig() backend.TemplateSyncerConfig {
	interval := 6 * time.Hour
	if v := os.Getenv("TEMPLATE_SYNC_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	repo := defaultTemplateRepo
	if v, ok := os.LookupEnv("TEMPLATE_SYNC_REPO"); ok {
		repo = v
	}
	return backend.TemplateSyncerConfig{
		Interval: interval,
		Repo:     repo,
		Ref:      envOr("TEMPLATE_SYNC_REF", "latest"),
		Dir:      envOr("TEMPLATE_SYNC_DIR", "/tmp/nsc-template-sync"),
	}
}
