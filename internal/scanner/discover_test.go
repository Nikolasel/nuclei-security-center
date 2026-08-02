package scanner

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func mustPair(t *testing.T, args []string, flag, val string) {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return
		}
	}
	t.Errorf("expected %s %s in args: %v", flag, val, args)
}

func TestBuildNaabuHostDiscoveryArgs(t *testing.T) {
	// Host-discovery pass: -sn, host discovery on, probing ICMP AND TCP 80/443 so a
	// host that blocks ping but serves the web is still found alive.
	args := buildNaabuHostDiscoveryArgs("/t/targets.txt", &types.DiscoveryOptions{Enabled: true})
	mustPair(t, args, "-list", "/t/targets.txt")
	mustPair(t, args, "-scan-type", "syn")
	mustPair(t, args, "-probe-tcp-syn", "80,443")
	mustPair(t, args, "-warm-up-time", "0")
	for _, want := range []string{"-sn", "-with-host-discovery", "-probe-icmp-echo"} {
		if !slices.Contains(args, want) {
			t.Errorf("expected %s in host-discovery args: %v", want, args)
		}
	}
	// The host-discovery pass lists alive IPs on stdout (fed to the port-scan pass as
	// -list) — no -output file, no JSON, and it never port-scans.
	if slices.Contains(args, "-output") || slices.Contains(args, "-json") ||
		slices.Contains(args, "-top-ports") || slices.Contains(args, "-port") {
		t.Errorf("host-discovery pass must not port-scan or write -output: %v", args)
	}
}

func TestBuildNaabuPortScanArgs(t *testing.T) {
	// Port-scan pass always skips host discovery (SYN: pass 1 did it; connect: no
	// raw sockets). SYN vs connect only changes the scan type.
	syn := buildNaabuPortScanArgs("/t/alive.txt", "/t/o.jsonl", scanTypeSYN, &types.DiscoveryOptions{Enabled: true})
	mustPair(t, syn, "-scan-type", "syn")
	mustPair(t, syn, "-top-ports", defaultTopPorts)
	for _, want := range []string{"-json", "-skip-host-discovery"} {
		if !slices.Contains(syn, want) {
			t.Errorf("expected %s in port-scan args: %v", want, syn)
		}
	}
	if slices.Contains(syn, "-with-host-discovery") {
		t.Errorf("port-scan pass must not re-run host discovery: %v", syn)
	}

	conn := buildNaabuPortScanArgs("/t/t.txt", "/t/o.jsonl", scanTypeConnect, &types.DiscoveryOptions{Enabled: true})
	mustPair(t, conn, "-scan-type", "connect")
	if !slices.Contains(conn, "-skip-host-discovery") {
		t.Errorf("connect mode must skip host discovery: %v", conn)
	}

	// Explicit ports => -port spec, and NO -top-ports.
	custom := buildNaabuPortScanArgs("/t/t.txt", "/t/o.jsonl", scanTypeSYN, &types.DiscoveryOptions{Enabled: true, Ports: "80,443,8000-9000"})
	mustPair(t, custom, "-port", "80,443,8000-9000")
	if slices.Contains(custom, "-top-ports") {
		t.Errorf("custom ports must not also pass -top-ports: %v", custom)
	}
}

func TestNaabuTuning(t *testing.T) {
	// Tuning knobs appear only when set (> 0), in both passes.
	none := buildNaabuPortScanArgs("/t/t.txt", "/t/o.jsonl", scanTypeSYN, &types.DiscoveryOptions{Enabled: true})
	for _, flag := range []string{"-rate", "-timeout", "-retries"} {
		if slices.Contains(none, flag) {
			t.Errorf("unset tuning knob %s must be omitted: %v", flag, none)
		}
	}
	tuned := &types.DiscoveryOptions{Enabled: true, Rate: 3000, ProbeTimeoutMs: 400, Retries: 1}
	for _, args := range [][]string{
		buildNaabuPortScanArgs("/t/t.txt", "/t/o.jsonl", scanTypeSYN, tuned),
		buildNaabuHostDiscoveryArgs("/t/t.txt", tuned),
	} {
		mustPair(t, args, "-rate", "3000")
		mustPair(t, args, "-timeout", "400")
		mustPair(t, args, "-retries", "1")
	}
}

func TestNormalizeScanType(t *testing.T) {
	for in, want := range map[string]string{
		"":          scanTypeSYN,
		"syn":       scanTypeSYN,
		"garbage":   scanTypeSYN,
		"connect":   scanTypeConnect,
		"Connect":   scanTypeConnect,
		" CONNECT ": scanTypeConnect,
	} {
		if got := normalizeScanType(in); got != want {
			t.Errorf("normalizeScanType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNaabuResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "disc.jsonl")
	content := `{"ip":"93.184.216.34","port":443,"host":"example.com"}
{"ip":"93.184.216.34","port":80,"host":"example.com"}
{"ip":"10.0.0.5","port":22}
{"ip":"93.184.216.34","port":443,"host":"example.com"}
{"ip":"2606:2800:220:1:248:1893:25c8:1946","port":8080}

not-json-but-hostish:9000
garbage line without colon
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseNaabuResults(path)
	if err != nil {
		t.Fatalf("parseNaabuResults: %v", err)
	}
	want := []string{
		"example.com:443",
		"example.com:80",
		"10.0.0.5:22", // no host => ip:port
		"[2606:2800:220:1:248:1893:25c8:1946]:8080", // IPv6 bracketed
		"not-json-but-hostish:9000",                 // plain host:port fallback
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseNaabuResults =\n %v\nwant\n %v", got, want)
	}
}

func TestDiscoveryWriterTally(t *testing.T) {
	var mirror bytes.Buffer
	var gotHosts, gotPorts int
	calls := 0
	// One tally shared across the two passes (host discovery, then port scan).
	tally := &discoveryTally{report: func(h, p int) { gotHosts, gotPorts = h, p; calls++ }}

	// Pass 1 writer: host discovery streams "Found alive host" as each host answers.
	// Feed in arbitrary chunks (split mid-line) to exercise the partial-line carry.
	w1 := &discoveryWriter{inner: &mirror, tally: tally}
	for _, c := range []string{
		"[INF] Running host discovery scan\n[INF] Found alive host 192.168.178.1 (192.168.178.1)\n",
		"[INF] Found alive host 192.168.178.33 (192",
		".168.178.33)\n[INF] Found alive host 192.168.178.50 (192.168.178.50)\n",
	} {
		if _, err := w1.Write([]byte(c)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// Pass 2 writer: a NEW writer sharing the SAME tally — the alive-host count from
	// pass 1 must persist while the port count fills in.
	w2 := &discoveryWriter{inner: &mirror, tally: tally}
	for _, c := range []string{
		"[INF] Found 3 ports on host 192.168.178.1 (192.168.178.1)\n",
		"[INF] Found 1 ports on host 192.168.178.33 (192.168.178.33)\n[WRN] noise line\n",
	} {
		if _, err := w2.Write([]byte(c)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// 3 hosts found alive (persists across passes); ports add up to 4. Host count
	// comes from the alive-host lines (3), not the port-host lines (2).
	if gotHosts != 3 || gotPorts != 4 {
		t.Errorf("tally = %d hosts / %d ports, want 3 / 4", gotHosts, gotPorts)
	}
	if calls != 5 {
		t.Errorf("report called %d times, want 5 (3 alive + 2 port lines)", calls)
	}
	// Everything is mirrored verbatim to the execution log.
	if !strings.Contains(mirror.String(), "Running host discovery scan") ||
		!strings.Contains(mirror.String(), "noise line") {
		t.Errorf("stderr not mirrored verbatim: %q", mirror.String())
	}
	// Each writer keeps its own tail for error messages (pass 2's here).
	if !strings.Contains(w2.tail(), "noise line") {
		t.Errorf("tail missing recent output: %q", w2.tail())
	}
}

func TestReadNonEmptyLinesDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alive.txt")
	content := "\n scanme.sh \nscanme.sh\n192.168.65.7\nscanme.sh\n 192.168.65.7 \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readNonEmptyLines(path)
	if err != nil {
		t.Fatalf("readNonEmptyLines: %v", err)
	}
	want := []string{"scanme.sh", "192.168.65.7"}
	if !slices.Equal(got, want) {
		t.Errorf("readNonEmptyLines = %v, want %v", got, want)
	}
}

func TestDiscoverPassesDeduplicatedHostsToPortScan(t *testing.T) {
	dir := t.TempDir()
	fakeNaabu := filepath.Join(dir, "fake-naabu")
	capture := filepath.Join(dir, "port-scan-input.txt")
	if err := os.WriteFile(fakeNaabu, []byte(`#!/bin/sh
set -eu
list=
output=
host_discovery=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -list) list="$2"; shift 2 ;;
    -output) output="$2"; shift 2 ;;
    -sn) host_discovery=1; shift ;;
    *) shift ;;
  esac
done
if [ "$host_discovery" -eq 1 ]; then
  printf 'scanme.sh\nscanme.sh\n192.168.65.7\n'
else
  cat "$list" > "$CAPTURE_FILE"
  : > "$output"
fi
`), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPTURE_FILE", capture)

	targetsFile := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetsFile, []byte("scanme.sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Runner{naabuPath: fakeNaabu, scanType: scanTypeSYN}
	if _, err := r.discover(context.Background(), types.ScanSpec{
		Options: types.ScanOptions{Discovery: &types.DiscoveryOptions{Enabled: true}},
	}, targetsFile, dir, io.Discard, nil); err != nil {
		t.Fatalf("discover: %v", err)
	}

	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read captured port-scan input: %v", err)
	}
	want := "scanme.sh\n192.168.65.7\n"
	if string(got) != want {
		t.Errorf("port-scan input = %q, want %q", got, want)
	}
}

func TestParseNaabuResultsMissingFile(t *testing.T) {
	// naabu produced nothing (no open ports) => empty, not an error.
	got, err := parseNaabuResults(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}
