package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

type commandLogRecord struct {
	phase string
	argv  []string
}

func parseCommandLog(t *testing.T, text string) []commandLogRecord {
	t.Helper()
	const prefix = "[CMD] phase="
	var records []commandLogRecord
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimPrefix(line, prefix)
		phase, encoded, ok := strings.Cut(rest, " argv=")
		if !ok || phase == "" {
			t.Fatalf("malformed command log line: %q", line)
		}
		var argv []string
		if err := json.Unmarshal([]byte(encoded), &argv); err != nil {
			t.Fatalf("decode command log line %q: %v", line, err)
		}
		records = append(records, commandLogRecord{phase: phase, argv: argv})
	}
	return records
}

func TestWriteCommandLogPreservesArgvAndPhase(t *testing.T) {
	var log bytes.Buffer
	args := []string{
		"-list", "/tmp/path with spaces/targets.txt",
		"-custom-flag", "value with spaces",
		"-templates", "/bundle/template.yaml",
	}

	writeCommandLog(&log, "nuclei", "/opt/tools/nuclei", args)

	records := parseCommandLog(t, log.String())
	if len(records) != 1 {
		t.Fatalf("got %d command records, want 1: %q", len(records), log.String())
	}
	if records[0].phase != "nuclei" {
		t.Errorf("phase = %q, want nuclei", records[0].phase)
	}
	want := append([]string{"/opt/tools/nuclei"}, args...)
	if !slices.Equal(records[0].argv, want) {
		t.Errorf("argv = %#v, want %#v", records[0].argv, want)
	}
}

func TestWriteCommandLogCompactsLargeTemplateArgv(t *testing.T) {
	const templateCount = 9000
	templatePaths := make([]string, templateCount)
	for i := range templatePaths {
		templatePaths[i] = fmt.Sprintf("/bundle/templates/template-%04d.yaml", i)
	}
	args := buildArgs(
		"/scan/targets.txt",
		"/scan/results.jsonl",
		"/scan/trace.fifo",
		templatePaths,
		types.ScanSpec{Options: types.ScanOptions{RateLimit: 42, MaxHostError: 100}},
	)
	var log bytes.Buffer
	writeCommandLog(&log, "nuclei", "/opt/tools/nuclei", args)

	if lines := strings.Count(log.String(), "\n"); lines != 1 {
		t.Fatalf("command log has %d lines, want one: %q", lines, log.String())
	}
	if len(log.Bytes()) >= 16*1024 {
		t.Fatalf("compacted command log is %d bytes, want less than 16 KiB", log.Len())
	}
	records := parseCommandLog(t, log.String())
	if len(records) != 1 {
		t.Fatalf("got %d command records, want 1", len(records))
	}
	const sampleEachSide = 4
	if !slices.Contains(records[0].argv, fmt.Sprintf(templatePathSummaryFormat, templateCount-2*sampleEachSide)) {
		t.Errorf("command log lacks template summary: %#v", records[0].argv)
	}
	for _, index := range []int{0, sampleEachSide - 1, templateCount - sampleEachSide, templateCount - 1} {
		if !slices.Contains(records[0].argv, templatePaths[index]) {
			t.Errorf("command log lost template sample %q: %#v", templatePaths[index], records[0].argv)
		}
	}
	for _, index := range []int{sampleEachSide, templateCount - sampleEachSide - 1} {
		if slices.Contains(records[0].argv, templatePaths[index]) {
			t.Errorf("command log retained omitted template path %q: %#v", templatePaths[index], records[0].argv)
		}
	}
	for _, arg := range []string{"-rate-limit", "42", "-max-host-error", "100"} {
		if !slices.Contains(records[0].argv, arg) {
			t.Errorf("command log lost non-template argument %q: %#v", arg, records[0].argv)
		}
	}
}

func TestWriteCommandLogRedactsSensitiveArguments(t *testing.T) {
	var log bytes.Buffer
	writeCommandLog(&log, "nuclei", "/opt/tools/nuclei", []string{
		"-list", "/tmp/targets.txt",
		"-token", "secret-token",
		"-H", "Authorization: Bearer secret-header",
		"-V", "apikey=sk-secret",
		"-sf", "/etc/nuclei/creds.yaml",
		"-itoken", "interact-secret",
		"-dtst", "dast-secret",
		"-ck", "/etc/nuclei/client.key",
		"-p", "http://user:pass@proxy",
		"-proxy-auth=user:pass",
		"--header=Authorization: Bearer secret-header=tail",
		"-password", "secret-password",
	})

	records := parseCommandLog(t, log.String())
	if len(records) != 1 {
		t.Fatalf("got %d command records, want 1: %q", len(records), log.String())
	}
	want := []string{
		"/opt/tools/nuclei",
		"-list", "/tmp/targets.txt",
		"-token", "[REDACTED]",
		"-H", "[REDACTED]",
		"-V", "[REDACTED]",
		"-sf", "[REDACTED]",
		"-itoken", "[REDACTED]",
		"-dtst", "[REDACTED]",
		"-ck", "[REDACTED]",
		"-p", "[REDACTED]",
		"-proxy-auth=[REDACTED]",
		"--header=[REDACTED]",
		"-password", "[REDACTED]",
	}
	if !slices.Equal(records[0].argv, want) {
		t.Errorf("redacted argv = %#v, want %#v", records[0].argv, want)
	}
	for _, secret := range []string{
		"secret-token", "secret-header", "sk-secret", "/etc/nuclei/creds.yaml",
		"interact-secret", "dast-secret", "/etc/nuclei/client.key", "user:pass", "secret-password",
	} {
		if strings.Contains(log.String(), secret) {
			t.Errorf("command log contains sensitive value %q: %q", secret, log.String())
		}
	}
}

func TestWriteCommandLogKeepsNaabuPortShortFlag(t *testing.T) {
	var log bytes.Buffer
	writeCommandLog(&log, "naabu-port-scan", "naabu", []string{
		"-p", "443,8443",
		"-rate", "1000",
	})

	records := parseCommandLog(t, log.String())
	if len(records) != 1 {
		t.Fatalf("got %d command records, want 1: %q", len(records), log.String())
	}
	want := []string{"naabu", "-p", "443,8443", "-rate", "1000"}
	if !slices.Equal(records[0].argv, want) {
		t.Errorf("naabu argv = %#v, want %#v", records[0].argv, want)
	}
}

func TestRunnerLogsNucleiCommandBeforeDiagnostics(t *testing.T) {
	dir := t.TempDir()
	fakeNuclei := filepath.Join(dir, "fake-nuclei")
	if err := os.WriteFile(fakeNuclei, []byte(`#!/bin/sh
set -eu
if [ "${1:-}" = "-version" ]; then
  printf 'nuclei v3.11.0\n'
  exit 0
fi
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -output) output="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '[INF] fake nuclei stderr\n' >&2
: > "$output"
`), 0o700); err != nil {
		t.Fatal(err)
	}

	j := &job{
		status:      types.ScanStatus{ID: "test-scan", State: types.ScanRunning},
		resultsPath: filepath.Join(dir, "results.jsonl"),
		logPath:     filepath.Join(dir, "scan.log"),
	}
	r := &Runner{nucleiPath: fakeNuclei}
	r.run(j, types.ScanSpec{Targets: []string{"scanme.sh"}}, dir, nil, func() {})

	log, err := os.ReadFile(j.logPath)
	if err != nil {
		t.Fatalf("read execution log: %v", err)
	}
	records := parseCommandLog(t, string(log))
	if len(records) != 1 || records[0].phase != "nuclei" {
		t.Fatalf("Nuclei command records = %#v, want one nuclei record", records)
	}
	if records[0].argv[0] != fakeNuclei {
		t.Errorf("logged executable = %q, want %q", records[0].argv[0], fakeNuclei)
	}
	if !slices.Contains(records[0].argv, "-list") || !slices.Contains(records[0].argv, filepath.Join(dir, "targets.txt")) {
		t.Errorf("logged argv lacks target list: %#v", records[0].argv)
	}
	if !slices.Contains(records[0].argv, "-output") || !slices.Contains(records[0].argv, j.resultsPath) {
		t.Errorf("logged argv lacks result output: %#v", records[0].argv)
	}
	commandOffset := strings.Index(string(log), "[CMD] phase=nuclei")
	diagnosticOffset := strings.Index(string(log), "[INF] fake nuclei stderr")
	if commandOffset < 0 || diagnosticOffset < 0 || commandOffset > diagnosticOffset {
		t.Errorf("Nuclei command was not logged before diagnostics: %q", log)
	}
}

func TestDiscoverCommandLogRecordsNaabuPasses(t *testing.T) {
	dir := t.TempDir()
	fakeNaabu := filepath.Join(dir, "fake-naabu")
	if err := os.WriteFile(fakeNaabu, []byte(`#!/bin/sh
set -eu
host_discovery=0
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -sn) host_discovery=1; shift ;;
    -output) output="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '[INF] fake naabu stderr\n' >&2
if [ "$host_discovery" -eq 1 ]; then
  printf 'scanme.sh\n'
else
  printf '{"ip":"93.184.216.34","port":443,"host":"scanme.sh"}\n' > "$output"
fi
`), 0o700); err != nil {
		t.Fatal(err)
	}
	targetsFile := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetsFile, []byte("scanme.sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	on := true
	r := &Runner{naabuPath: fakeNaabu, scanType: scanTypeConnect}
	var log bytes.Buffer
	if _, err := r.discover(context.Background(), types.ScanSpec{
		Options: types.ScanOptions{Discovery: &types.DiscoveryOptions{
			Enabled: true, ScanType: scanTypeConnect, HostDiscovery: &on,
		}},
	}, targetsFile, dir, &log, nil); err != nil {
		t.Fatalf("discover with host discovery: %v", err)
	}

	records := parseCommandLog(t, log.String())
	if len(records) != 2 {
		t.Fatalf("got %d command records with host discovery, want 2: %q", len(records), log.String())
	}
	if got := []string{records[0].phase, records[1].phase}; !slices.Equal(got, []string{"naabu-host-discovery", "naabu-port-scan"}) {
		t.Errorf("phases = %#v, want host-discovery then port-scan", got)
	}
	if !slices.Contains(records[0].argv, "-sn") {
		t.Errorf("host-discovery argv lacks -sn: %#v", records[0].argv)
	}
	if !slices.Contains(records[1].argv, "-scan-type") || !slices.Contains(records[1].argv, "connect") {
		t.Errorf("connect port-scan argv lacks connect mode: %#v", records[1].argv)
	}
	firstCommand := strings.Index(log.String(), "[CMD] phase=naabu-host-discovery")
	firstOutput := strings.Index(log.String(), "[INF] fake naabu stderr")
	secondCommand := strings.Index(log.String(), "[CMD] phase=naabu-port-scan")
	secondOutput := strings.LastIndex(log.String(), "[INF] fake naabu stderr")
	if firstCommand < 0 || firstOutput < 0 || secondCommand < 0 || secondOutput < 0 ||
		firstCommand > firstOutput || secondCommand > secondOutput || firstOutput > secondCommand {
		t.Errorf("command/output ordering is wrong: %q", log.String())
	}

	// An explicit opt-out must produce only the port-scan command.
	off := false
	log.Reset()
	if _, err := r.discover(context.Background(), types.ScanSpec{
		Options: types.ScanOptions{Discovery: &types.DiscoveryOptions{
			Enabled: true, ScanType: scanTypeConnect, HostDiscovery: &off,
		}},
	}, targetsFile, dir, &log, nil); err != nil {
		t.Fatalf("discover without host discovery: %v", err)
	}
	records = parseCommandLog(t, log.String())
	if len(records) != 1 || records[0].phase != "naabu-port-scan" {
		t.Fatalf("phases without host discovery = %#v, want only naabu-port-scan", records)
	}
	if slices.Contains(records[0].argv, "-sn") {
		t.Errorf("port-scan-only argv unexpectedly contains -sn: %#v", records[0].argv)
	}
}
