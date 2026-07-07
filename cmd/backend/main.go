// Command backend is the system of record and orchestrator. It owns Postgres,
// dispatches scans to a scanner node, polls to completion, and ingests findings.
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

	"github.com/Nikolasel/nuclei-security-center/internal/backend"
	"github.com/Nikolasel/nuclei-security-center/internal/store"
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

	ctx := context.Background()
	st, err := openStoreWithRetry(ctx, dsn, log)
	if err != nil {
		log.Error("connect store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	}
	log.Info("migrations applied")

	client := backend.NewScannerClient(scannerURL, scannerToken)
	orch := backend.NewOrchestrator(st, client, log)

	srv := &http.Server{
		Addr:              addr,
		Handler:           backend.NewServer(st, orch, log).Handler(),
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

// openStoreWithRetry tolerates Postgres not being ready yet (compose startup).
func openStoreWithRetry(ctx context.Context, dsn string, log *slog.Logger) (*store.Store, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		st, err := store.Open(ctx, dsn)
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
