// Command scanner is the credential-less Nuclei execution node. It exposes the
// /v1 scan API (bearer-auth) and shells out to the nuclei binary. It has no
// database access and never calls back to the backend.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/scanner"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	addr := envOr("SCANNER_ADDR", ":8081")
	token := os.Getenv("SCANNER_TOKEN")
	if !scannerTokenOK(token) {
		// The bearer token is the sole control over this credential-less node,
		// so enforce a strength floor — anyone reaching the node with it bypasses
		// the backend's scope guardrail entirely.
		log.Error("SCANNER_TOKEN must be set and at least 32 characters", "min", minScannerTokenLen, "got", len(token))
		os.Exit(1)
	}
	nucleiPath := envOr("NUCLEI_PATH", "nuclei")
	workRoot, err := resolveWorkDir(os.Getenv("SCANNER_WORK_DIR"))
	if err != nil {
		log.Error("prepare work dir", "err", err)
		os.Exit(1)
	}

	runner, err := scanner.NewRunner(nucleiPath, workRoot)
	if err != nil {
		log.Error("init runner", "err", err)
		os.Exit(1)
	}

	// Optional TLS / mTLS (#26). Unset ⇒ plain HTTP (unchanged). When a server
	// cert is configured the node serves HTTPS; when a client CA is also set it
	// requires + verifies a client cert (mTLS) — the bearer token still applies.
	tlsCfg, err := scanner.ServerTLSFromEnv()
	if err != nil {
		log.Error("configure scanner TLS", "err", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           scanner.NewServer(runner, token, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsCfg,
	}

	go func() {
		log.Info("scanner node listening", "addr", addr, "nuclei", nucleiPath,
			"tls", tlsCfg != nil, "mtls", scanner.RequiresClientCert(tlsCfg))
		var err error
		if tlsCfg != nil {
			// Certs live in TLSConfig, so the file args are empty.
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	waitForShutdown(log, srv)
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

// minScannerTokenLen is the minimum accepted SCANNER_TOKEN length. 32 chars is
// the length of a base64url-encoded 24-byte CSPRNG value — the recommended way
// to mint the token.
const minScannerTokenLen = 32

func scannerTokenOK(token string) bool {
	return len(token) >= minScannerTokenLen
}

// resolveWorkDir returns the per-scan work root. An explicit SCANNER_WORK_DIR is
// honored as-is (operator-managed, e.g. a mounted private volume). When unset,
// a process-exclusive directory with 0700 perms is created under the system
// temp dir instead of the old predictable /tmp/nuclei-scans — os.MkdirTemp
// generates an unguessable name and fails rather than reusing an existing path,
// closing the symlink/pre-creation window on a shared host.
func resolveWorkDir(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	return os.MkdirTemp("", "nuclei-scans-")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
