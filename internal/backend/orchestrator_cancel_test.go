package backend

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestPollToDoneAcceptsCancelledNodeStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"node-1","state":"cancelled"}`)
	}))
	defer server.Close()

	orch := &Orchestrator{
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		pollInterval: time.Millisecond,
		progress:     make(map[string]*types.ScanProgress),
		discovered:   make(map[string][]string),
	}
	status, err := orch.pollToDone(
		context.Background(),
		NewScannerClient(server.URL, "scanner-token"),
		"scan-1",
		"node-1",
		time.Second,
	)
	if err != nil {
		t.Fatalf("pollToDone: %v", err)
	}
	if status.State != types.ScanCancelled {
		t.Fatalf("status state = %q, want %q", status.State, types.ScanCancelled)
	}
}
