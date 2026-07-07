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
	if token == "" {
		log.Error("SCANNER_TOKEN is required")
		os.Exit(1)
	}
	nucleiPath := envOr("NUCLEI_PATH", "nuclei")
	workRoot := envOr("SCANNER_WORK_DIR", "/tmp/nuclei-scans")

	runner, err := scanner.NewRunner(nucleiPath, workRoot)
	if err != nil {
		log.Error("init runner", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           scanner.NewServer(runner, token, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("scanner node listening", "addr", addr, "nuclei", nucleiPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
