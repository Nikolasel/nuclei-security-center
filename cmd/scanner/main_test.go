package main

import (
	"os"
	"strings"
	"testing"
)

func TestScannerTokenOK(t *testing.T) {
	if scannerTokenOK("") {
		t.Error("empty token accepted")
	}
	if scannerTokenOK(strings.Repeat("a", minScannerTokenLen-1)) {
		t.Errorf("token below %d chars accepted", minScannerTokenLen)
	}
	if !scannerTokenOK(strings.Repeat("a", minScannerTokenLen)) {
		t.Errorf("token of exactly %d chars rejected", minScannerTokenLen)
	}
}

func TestResolveWorkDir(t *testing.T) {
	// Explicit value is honored as-is.
	if got, err := resolveWorkDir("/mnt/scans"); err != nil || got != "/mnt/scans" {
		t.Errorf("resolveWorkDir(explicit) = (%q, %v), want (/mnt/scans, nil)", got, err)
	}

	// Unset -> a private, process-exclusive dir with 0700 perms.
	dir, err := resolveWorkDir("")
	if err != nil {
		t.Fatalf("resolveWorkDir(\"\"): %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	if dir == "/tmp/nuclei-scans" {
		t.Error("fell back to the predictable shared path")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("work dir perms = %o, want 0700", perm)
	}
}
