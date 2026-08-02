package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// defaultDiscoveryTimeout caps the naabu pre-pass when the policy sets no
// explicit discovery TimeoutSec. It is deliberately separate from the Nuclei
// timeout so a slow discovery can't silently eat the scan's Nuclei budget (#86).
const defaultDiscoveryTimeout = 5 * time.Minute

// defaultTopPorts is naabu's port set when the policy names no explicit ports —
// the nmap top-1000, a good speed/coverage balance for CIDR-scoped targets.
const defaultTopPorts = "1000"

// naabuResult is the subset of naabu's -json output we consume. host is the
// original input host when naabu resolved it from a hostname; ip is always the
// reachable address. We prefer host (so Nuclei keeps the vhost/TLS SNI) and fall
// back to ip (CIDR/IP inputs have no host).
type naabuResult struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Host string `json:"host"`
}

// discover runs the naabu pre-pass over the scan's targets and returns the
// narrowed, deduplicated list of live host:port entries for Nuclei. It runs naabu
// as a subprocess (invariant #3: a binary, not a linked SDK) in its own process
// group so ctx cancel/timeout kills it and any child. It FAILS CLOSED: a missing
// binary, non-zero exit, or timeout is returned as an error, and the caller aborts
// the scan — it never falls back to scanning every host unfiltered. An empty
// (non-error) return means naabu ran fine and found no live host:port.
//
// In SYN mode it runs TWO naabu passes: a host-discovery pass (`-sn`) then a
// port-scan of just the live hosts. The split is deliberate — naabu only streams
// its "Found alive host" lines in `-sn` mode, so the first pass gives a LIVE host
// count for the UI (a full combined scan reports nothing until it finishes). The
// total work is the same: the port-scan pass skips host discovery since the first
// pass already did it. In connect mode (unprivileged, no host discovery) it is a
// single port-scan pass over every host.
//
// naabu's stderr (banner + diagnostics) is mirrored to logw, the same execution-
// log archive Nuclei's stderr lands in (#94); the same stream is parsed for the
// live discovery tally.
func (r *Runner) discover(ctx context.Context, spec types.ScanSpec, targetsFile, dir string, logw io.Writer, onProgress func(hosts, ports int)) ([]string, error) {
	tally := &discoveryTally{report: onProgress}
	scanInput := targetsFile

	// The policy may pick the scan mode per-scan (#86); an empty value falls back to
	// the node's own NAABU_SCAN_TYPE default. Requesting "syn" on a node without raw
	// sockets simply fails closed below.
	scanType := r.scanType
	if st := spec.Options.Discovery.ScanType; st != "" {
		scanType = normalizeScanType(st)
	}

	if scanType == scanTypeSYN {
		// Pass 1: host discovery only — streams "Found alive host" ⇒ live host count,
		// and lists the alive host IPs on stdout, which we capture to aliveFile.
		aliveFile := filepath.Join(dir, "alive.txt")
		f, err := os.OpenFile(aliveFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return nil, fmt.Errorf("create alive-hosts file: %w", err)
		}
		runErr := r.runNaabu(ctx, buildNaabuHostDiscoveryArgs(targetsFile, spec.Options.Discovery), f, logw, tally)
		f.Close()
		if runErr != nil {
			return nil, fmt.Errorf("host discovery: %w", runErr)
		}
		alive, err := readNonEmptyLines(aliveFile)
		if err != nil {
			return nil, fmt.Errorf("read alive hosts: %w", err)
		}
		if len(alive) == 0 {
			return nil, nil // no live hosts ⇒ nothing to port-scan
		}
		scanInput = aliveFile
	}

	// Port-scan pass. Host discovery is skipped either way here: in SYN mode pass 1
	// already did it (scanInput is the alive list); in connect mode it needs raw
	// sockets we don't have. Results go to the -output file (stdout discarded).
	outFile := filepath.Join(dir, "discovery.jsonl")
	if err := r.runNaabu(ctx, buildNaabuPortScanArgs(scanInput, outFile, scanType, spec.Options.Discovery), io.Discard, logw, tally); err != nil {
		return nil, err
	}
	return parseNaabuResults(outFile)
}

// runNaabu executes one naabu invocation, sending its stdout to stdout (the host-
// discovery pass captures the alive list there; the port-scan pass discards it) and
// mirroring stderr to logw (the execution log) while parsing it into tally for the
// live progress signal. It runs in its own process group so ctx cancel/timeout
// kills naabu and any child, and maps a deadline to a clear "timed out" error
// (fail-closed).
func (r *Runner) runNaabu(ctx context.Context, args []string, stdout, logw io.Writer, tally *discoveryTally) error {
	cmd := exec.CommandContext(ctx, r.naabuPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	dw := &discoveryWriter{inner: logw, tally: tally}
	cmd.Stdout = stdout
	cmd.Stderr = dw
	if err := cmd.Run(); err != nil {
		// A timeout gets a clean message — the OS reason and stderr tail only bury
		// the cause; the full naabu stderr is in the execution-log archive (#94).
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out (see execution log for details)")
		}
		msg := strings.TrimSpace(lastLines(dw.tail(), 20))
		return fmt.Errorf("%v: %s", err, msg)
	}
	return nil
}

// readNonEmptyLines reads a file into a slice of its non-blank, trimmed, unique
// lines. The SYN host-discovery pass can print a hostname once per resolved
// address (for example, once for IPv4 and once for IPv6); forwarding those
// duplicates into the port-scan pass would make its live tally count the same
// host's ports more than once. A missing file (naabu found nothing) is an empty
// slice, not an error.
func readNonEmptyLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	seen := make(map[string]struct{})
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			if _, exists := seen[s]; exists {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

// Scan-type modes for the naabu pre-pass, selected by the node's NAABU_SCAN_TYPE.
const (
	// scanTypeSYN is the default: a SYN scan preceded by host discovery, so naabu
	// prunes dead hosts before port-scanning — the big win on sparse ranges. It
	// needs raw sockets (CAP_NET_RAW, present in Docker's default caps) + libpcap
	// (bundled in the image).
	scanTypeSYN = "syn"
	// scanTypeConnect is the unprivileged fallback: a TCP connect scan with no host
	// discovery (its probes need raw sockets). Needs no capabilities or libpcap, but
	// scans every host's ports, so it's slower on sparse ranges. For locked-down
	// deployments that drop NET_RAW.
	scanTypeConnect = "connect"
)

// normalizeScanType maps a NAABU_SCAN_TYPE value to a supported mode, defaulting
// to SYN. Anything other than a case-insensitive "connect" is treated as SYN.
func normalizeScanType(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), scanTypeConnect) {
		return scanTypeConnect
	}
	return scanTypeSYN
}

// naabuBaseArgs are the flags common to every naabu invocation: no 2s inter-phase
// warm-up, a clean update-free log. Output handling differs per pass (the host-
// discovery pass prints alive hosts to stdout; the port-scan pass writes JSON to a
// -output file), so callers add that.
func naabuBaseArgs(targetsFile string) []string {
	return []string{
		"-list", targetsFile,
		"-warm-up-time", "0",
		"-no-color",
		"-disable-update-check",
	}
}

// appendTuning adds the optional per-policy tuning flags (#86). Each <= 0 leaves
// naabu's own default. They let an operator trade completeness for speed on their
// range (e.g. lower timeout/retries on a fast LAN) and apply to every pass.
func appendTuning(args []string, d *types.DiscoveryOptions) []string {
	if d.Rate > 0 {
		args = append(args, "-rate", strconv.Itoa(d.Rate))
	}
	if d.ProbeTimeoutMs > 0 {
		args = append(args, "-timeout", strconv.Itoa(d.ProbeTimeoutMs))
	}
	if d.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(d.Retries))
	}
	return args
}

// buildNaabuHostDiscoveryArgs assembles the SYN-mode host-discovery pass (`-sn`),
// which prints "Found alive host" as each host answers (the live signal) and lists
// the alive host IPs on STDOUT (naabu writes -sn results to stdout, not -output —
// the caller captures stdout). It probes ICMP echo AND a TCP SYN/ACK ping to the
// common web ports, so a host that blocks ICMP but serves 80/443 (typical on the
// internet) is still detected as alive rather than skipped.
func buildNaabuHostDiscoveryArgs(targetsFile string, d *types.DiscoveryOptions) []string {
	args := append(naabuBaseArgs(targetsFile),
		"-sn",
		"-scan-type", "syn",
		"-with-host-discovery",
		"-probe-icmp-echo",
		"-probe-tcp-syn", "80,443",
		"-probe-tcp-ack", "443",
	)
	return appendTuning(args, d)
}

// buildNaabuPortScanArgs assembles the port-scan pass, writing JSON results to out.
// Host discovery is always skipped here: in SYN mode the host-discovery pass already
// ran (input is the alive list); in connect mode (unprivileged) its raw-socket
// probes aren't available.
func buildNaabuPortScanArgs(targetsFile, out, scanType string, d *types.DiscoveryOptions) []string {
	args := append(naabuBaseArgs(targetsFile), "-json", "-output", out, "-skip-host-discovery")
	if scanType == scanTypeConnect {
		args = append(args, "-scan-type", "connect")
	} else {
		args = append(args, "-scan-type", "syn")
	}
	if ports := strings.TrimSpace(d.Ports); ports != "" {
		args = append(args, "-port", ports)
	} else {
		args = append(args, "-top-ports", defaultTopPorts)
	}
	return appendTuning(args, d)
}

// parseNaabuResults reads naabu's output file into a deduplicated, ordered slice
// of host:port targets for Nuclei. It tolerates both JSON lines (naabu -json) and
// plain "host:port" lines, so it is robust to naabu's output-format quirks. A
// missing file means naabu found nothing → empty (not an error).
func parseNaabuResults(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read discovery output: %w", err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var out []string
	add := func(t string) {
		if t == "" {
			return
		}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line[0] == '{' {
			var r naabuResult
			if err := json.Unmarshal([]byte(line), &r); err != nil || r.Port == 0 {
				continue
			}
			hostpart := r.Host
			if hostpart == "" {
				hostpart = r.IP
			}
			add(joinHostPort(hostpart, r.Port))
			continue
		}
		// Plain "host:port" fallback — pass through verbatim if it looks valid.
		if strings.LastIndex(line, ":") > 0 {
			add(line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan discovery output: %w", err)
	}
	return out, nil
}

// naabu exposes no usable stats feed (#86), so its own log lines are the live
// discovery signal. Two matter:
//   - naabuAliveHostRe: "[INF] Found alive host 192.168.178.1 (192.168.178.1)" —
//     emitted during the host-discovery phase (SYN mode) AS each host is found, so
//     it streams a live "hosts alive" count while discovery runs.
//   - naabuFoundPortsRe: "[INF] Found 3 ports on host 192.168.178.1 (...)" —
//     emitted per host during the port-scan phase (both modes); it carries the open
//     port count but arrives late (naabu prints it as each host's scan completes).
var (
	naabuAliveHostRe  = regexp.MustCompile(`Found alive host `)
	naabuFoundPortsRe = regexp.MustCompile(`Found (\d+) ports? on host`)
)

// discoveryTailMax bounds the retained stderr tail used for error messages.
const discoveryTailMax = 4096

// discoveryTally accumulates the live discovery counts ACROSS naabu passes (host
// discovery then port scan), so the alive-host count found in pass 1 persists into
// pass 2 while the port count fills in. report is invoked on every update (it hops
// to the job's mutex). The mutex guards it against the two passes' writer
// goroutines — they run sequentially, but the lock keeps that a non-assumption.
type discoveryTally struct {
	report func(hosts, ports int)

	mu         sync.Mutex
	aliveHosts int // "Found alive host" lines (streams live during host discovery)
	portHosts  int // "Found N ports on host" lines (arrives late)
	ports      int // total open ports found
}

func (t *discoveryTally) addAliveHost() {
	t.mu.Lock()
	t.aliveHosts++
	t.emitLocked()
	t.mu.Unlock()
}

func (t *discoveryTally) addPorts(n int) {
	t.mu.Lock()
	t.portHosts++
	t.ports += n
	t.emitLocked()
	t.mu.Unlock()
}

func (t *discoveryTally) emitLocked() {
	if t.report == nil {
		return
	}
	// Report the larger host count: alive-host lines lead (host discovery runs
	// first), and every host with open ports was necessarily alive — so this is
	// monotonic and covers connect mode too (no alive-host lines ⇒ portHosts).
	hosts := t.aliveHosts
	if t.portHosts > hosts {
		hosts = t.portHosts
	}
	t.report(hosts, t.ports)
}

// discoveryWriter is one naabu invocation's stderr sink. It mirrors every byte to
// inner (the execution-log archive, #94) and parses complete lines into the shared
// tally. It retains a bounded tail for error reporting. Write is only called by the
// exec stderr copy goroutine and tail() only after Run() returns.
type discoveryWriter struct {
	inner io.Writer
	tally *discoveryTally

	buf   []byte // partial-line carry
	tailB []byte // bounded tail for error messages
}

func (w *discoveryWriter) Write(p []byte) (int, error) {
	if w.inner != nil {
		_, _ = w.inner.Write(p)
	}
	w.tailB = append(w.tailB, p...)
	if len(w.tailB) > discoveryTailMax {
		w.tailB = w.tailB[len(w.tailB)-discoveryTailMax:]
	}
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.handleLine(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

func (w *discoveryWriter) handleLine(line []byte) {
	if w.tally == nil {
		return
	}
	switch {
	case naabuAliveHostRe.Match(line):
		w.tally.addAliveHost()
	case naabuFoundPortsRe.Match(line):
		if m := naabuFoundPortsRe.FindSubmatch(line); m != nil {
			if n, err := strconv.Atoi(string(m[1])); err == nil {
				w.tally.addPorts(n)
			}
		}
	}
}

func (w *discoveryWriter) tail() string { return string(w.tailB) }

// joinHostPort builds a "host:port" target, bracketing IPv6 literals so Nuclei
// parses the port correctly.
func joinHostPort(host string, port int) string {
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") { // IPv6 literal
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}
