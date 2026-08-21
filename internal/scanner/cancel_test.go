package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestCancelPublishesTerminalStateAfterRunFinishes(t *testing.T) {
	cancelCalled := make(chan struct{})
	cancelReturned := make(chan bool, 1)
	runner := &Runner{scans: make(map[string]*job)}
	runner.scans["scan-1"] = &job{
		status: types.ScanStatus{ID: "scan-1", State: types.ScanRunning},
		cancel: func() { close(cancelCalled) },
		done:   make(chan struct{}),
	}

	go func() { cancelReturned <- runner.Cancel("scan-1") }()
	select {
	case <-cancelCalled:
	case <-time.After(time.Second):
		t.Fatal("Cancel did not invoke the scan cancel function")
	}

	status, ok := runner.Status("scan-1")
	if !ok {
		t.Fatal("running scan disappeared from runner")
	}
	if status.State != types.ScanRunning {
		t.Fatalf("state during cancellation = %q, want %q until run finishes", status.State, types.ScanRunning)
	}

	runner.scans["scan-1"].finish()
	select {
	case cancelled := <-cancelReturned:
		if !cancelled {
			t.Fatal("Cancel returned false for a running scan")
		}
	case <-time.After(time.Second):
		t.Fatal("Cancel did not return after run finished")
	}
	status, _ = runner.Status("scan-1")
	if status.State != types.ScanCancelled {
		t.Fatalf("final state = %q, want %q", status.State, types.ScanCancelled)
	}
}

func TestRunnerCancelDuringVersionProbeKillsProcessGroup(t *testing.T) {
	workRoot := t.TempDir()
	markers := t.TempDir()

	fakeNuclei := filepath.Join(workRoot, "fake-nuclei")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
markers=%q
if [ "${1:-}" = "-version" ]; then
  : > "$markers/version-started"
  (sleep 1; : > "$markers/version-child-finished") &
  while :; do sleep 1; done
fi
: > "$markers/nuclei-started"
sleep 30
`, markers)
	if err := os.WriteFile(fakeNuclei, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(fakeNuclei, "/bin/false", "connect", workRoot, 1)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	defer runner.Close()

	bundle := makeBundle(t, []bundleFile{{name: "custom/test.yaml", content: "id: test\n"}}, nil, nil)
	bundleStatus, err := runner.ApplyBundle(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("ApplyBundle: %v", err)
	}

	id, err := runner.Start(types.ScanSpec{
		Targets: []string{"scanme.sh"},
		Templates: types.TemplateSelector{
			TemplateIDs:     []string{"custom/test.yaml"},
			TemplatesCommit: bundleStatus.TemplatesCommit,
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForMarker(t, filepath.Join(markers, "version-started"))

	if !runner.Cancel(id) {
		t.Fatal("Cancel returned false for a running scan")
	}
	status, ok := runner.Status(id)
	if !ok {
		t.Fatal("cancelled scan disappeared from runner")
	}
	if status.State != types.ScanCancelled {
		t.Fatalf("scan state = %q, want %q", status.State, types.ScanCancelled)
	}

	// The delayed child shares the version probe's process group. If cancellation
	// only killed the shell, it would survive and create this marker.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(markers, "version-child-finished")); !os.IsNotExist(err) {
		t.Fatalf("version probe child survived cancellation: stat error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(markers, "nuclei-started")); !os.IsNotExist(err) {
		t.Fatalf("nuclei launched after cancellation: stat error=%v", err)
	}

	if err := runner.DeleteScan(id); err != nil {
		t.Fatalf("DeleteScan cancelled scan: %v", err)
	}
}

func waitForMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for marker %s", path)
}
