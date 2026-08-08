// Package scanner is the credential-less execution engine. It runs the Nuclei
// binary against a ScanSpec and serves the results back over HTTP. It holds no
// database access and initiates no connection back to the backend.
package scanner

import (
	"bufio"
	"context"
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

// Runner owns all in-flight and finished scans for this node. Scans live in
// memory only — the node is disposable; the backend is the system of record.
type Runner struct {
	nucleiPath string
	naabuPath  string
	scanType   string // naabu scan mode for discovery: "syn" (default) or "connect" (#86)
	workRoot   string
	bundle     *bundleStore // node-managed active template tree pushed by the backend (#85)

	mu    sync.Mutex
	scans map[string]*job
}

type job struct {
	mu          sync.Mutex
	status      types.ScanStatus
	phase       types.ScanPhase // current stage; stamped onto every progress snapshot (#86)
	resultsPath string
	logPath     string // Nuclei's stdout/stderr for this run (#94)
	cancel      context.CancelFunc
}

const coverageDrainTimeout = 5 * time.Second

// NewRunner prepares a Runner. workRoot is where per-scan temp dirs live.
// naabuPath is the naabu binary used for the optional port-discovery pre-pass
// (#86); it is only invoked when a scan spec opts into discovery. scanType is the
// naabu mode ("syn" or "connect"); it is normalized, so any unrecognized value
// (including "") falls back to the SYN default.
func NewRunner(nucleiPath, naabuPath, scanType, workRoot string) (*Runner, error) {
	if err := os.MkdirAll(workRoot, 0o750); err != nil {
		return nil, fmt.Errorf("create work root: %w", err)
	}
	// The template bundle lives alongside per-scan dirs under workRoot. A UUID scan
	// id never collides with this fixed name. Point SCANNER_WORK_DIR at a persistent
	// volume to keep the applied bundle across restarts.
	bundle, err := newBundleStore(filepath.Join(workRoot, "_bundle"))
	if err != nil {
		return nil, err
	}
	return &Runner{
		nucleiPath: nucleiPath,
		naabuPath:  naabuPath,
		scanType:   normalizeScanType(scanType),
		workRoot:   workRoot,
		bundle:     bundle,
		scans:      make(map[string]*job),
	}, nil
}

// ApplyBundle verifies and activates a template bundle pushed by the backend
// (#85). It is the node's receive side of the strictly backend→node transfer.
func (r *Runner) ApplyBundle(body io.Reader) (types.TemplateBundleStatus, error) {
	return r.bundle.apply(body)
}

// Start launches a scan asynchronously and returns its node-local id. The scan
// runs in its own goroutine; callers poll Status and read Results.
func (r *Runner) Start(spec types.ScanSpec) (string, error) {
	if len(spec.Targets) == 0 {
		return "", fmt.Errorf("scan spec has no targets")
	}
	templates, unlockTemplates, err := r.bundle.lockTemplates(
		spec.Templates.TemplateIDs,
		spec.Templates.TemplatesCommit,
	)
	if err != nil {
		return "", err
	}
	id := types.NewID()
	dir := filepath.Join(r.workRoot, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		unlockTemplates()
		return "", fmt.Errorf("create scan dir: %w", err)
	}

	j := &job{
		status: types.ScanStatus{
			ID:              id,
			State:           types.ScanRunning,
			TemplatesCommit: spec.Templates.TemplatesCommit,
		},
		resultsPath: filepath.Join(dir, "results.jsonl"),
		logPath:     filepath.Join(dir, "scan.log"),
	}
	r.mu.Lock()
	r.scans[id] = j
	r.mu.Unlock()

	go r.run(j, spec, dir, templates, unlockTemplates)
	return id, nil
}

// Status returns a snapshot of the scan's status, or ok=false if unknown.
func (r *Runner) Status(id string) (types.ScanStatus, bool) {
	r.mu.Lock()
	j, ok := r.scans[id]
	r.mu.Unlock()
	if !ok {
		return types.ScanStatus{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status, true
}

// ResultsPath returns the JSONL results file path for a scan, or ok=false.
func (r *Runner) ResultsPath(id string) (string, bool) {
	r.mu.Lock()
	j, ok := r.scans[id]
	r.mu.Unlock()
	if !ok {
		return "", false
	}
	return j.resultsPath, true
}

// LogPath returns the execution-log file path for a scan (Nuclei's stdout/stderr,
// #94), or ok=false if the scan is unknown.
func (r *Runner) LogPath(id string) (string, bool) {
	r.mu.Lock()
	j, ok := r.scans[id]
	r.mu.Unlock()
	if !ok {
		return "", false
	}
	return j.logPath, true
}

// Cancel stops a running scan by killing its process group.
func (r *Runner) Cancel(id string) bool {
	r.mu.Lock()
	j, ok := r.scans[id]
	r.mu.Unlock()
	if !ok {
		return false
	}
	j.mu.Lock()
	cancel := j.cancel
	j.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

func (r *Runner) run(j *job, spec types.ScanSpec, dir string, templates []lockedTemplate, unlockTemplates func()) {
	// Start acquired the active bundle's shared lock after validating the
	// manifest. Hold it across discovery and Nuclei so no bundle activation can
	// swap the selected files under this scan.
	defer unlockTemplates()

	// Capture the engine version before the scan so the backend can record
	// exactly what ran alongside the bundle digest.
	version := r.nucleiVersion()
	j.setVersion(version)

	// The execution-log archive (#94) captures both pipeline stages: the optional
	// naabu discovery pass and Nuclei. Open it once here and share the handle —
	// discovery runs to completion before Nuclei, so writes stay ordered. A log
	// file we can't open just disables the archive for this run (best-effort); the
	// scan itself is unaffected.
	var logw io.Writer = io.Discard
	if logFile, ferr := os.Create(j.logPath); ferr == nil {
		defer logFile.Close()
		logw = logFile
	}

	targetsFile := filepath.Join(dir, "targets.txt")
	if err := writeTargetsFile(targetsFile, spec.Targets); err != nil {
		j.fail(fmt.Errorf("write targets file: %w", err))
		return
	}

	// Optional naabu port-discovery pre-pass (#86). Fails closed: if discovery
	// errors, the scan fails rather than falling back to an unfiltered Nuclei run.
	// A clean run with no open ports means there is nothing for Nuclei to do.
	nucleiTargets := targetsFile
	if d := spec.Options.Discovery; d != nil && d.Enabled {
		j.setPhase(types.PhaseDiscovering)
		j.setDiscoveryProgress(0, 0)
		discTimeout := time.Duration(d.TimeoutSec) * time.Second
		if discTimeout <= 0 {
			discTimeout = defaultDiscoveryTimeout
		}
		dctx, dcancel := context.WithTimeout(context.Background(), discTimeout)
		j.setCancel(dcancel)
		live, err := r.discover(dctx, spec, targetsFile, dir, logw, j.setDiscoveryProgress)
		dcancel()
		if err != nil {
			j.fail(fmt.Errorf("port discovery (naabu): %w", err))
			return
		}
		j.setDiscoveredTargets(live)
		if len(live) == 0 {
			j.setCoverage([]types.EndpointCoverage{}, "")
			j.complete(0)
			return
		}
		nucleiTargets = filepath.Join(dir, "nuclei-targets.txt")
		if err := os.WriteFile(nucleiTargets, []byte(strings.Join(live, "\n")+"\n"), 0o640); err != nil {
			j.fail(fmt.Errorf("write discovered targets file: %w", err))
			return
		}
	}
	j.setPhase(types.PhaseScanning)

	timeout := time.Duration(spec.Options.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	j.setCancel(cancel)
	defer cancel()

	templatePaths := make([]string, 0, len(templates))
	templateIDByPath := make(map[string]string, len(templates))
	for _, template := range templates {
		templatePaths = append(templatePaths, template.Path)
		templateIDByPath[filepath.Clean(template.Path)] = template.ID
	}

	// Nuclei requires a path for -trace-log. Use a FIFO instead of a regular
	// file: coverage is reduced concurrently while Nuclei runs, so templates ×
	// targets request volume can never consume unbounded node disk (#91 review).
	tracePath := filepath.Join(dir, "requests-trace.pipe")
	if err := syscall.Mkfifo(tracePath, 0o600); err != nil {
		j.fail(fmt.Errorf("create endpoint coverage pipe: %w", err))
		return
	}
	defer os.Remove(tracePath)
	traceReader, traceAnchor, err := openCoverageTraceFIFO(tracePath)
	if err != nil {
		j.fail(fmt.Errorf("prepare endpoint coverage pipe: %w", err))
		return
	}
	defer traceReader.Close()
	defer traceAnchor.Close()
	coverageCh := make(chan coverageResult, 1)
	go func() {
		coverageCh <- coveredEndpointsFromTrace(traceReader, templateIDByPath)
	}()

	args := buildArgs(nucleiTargets, j.resultsPath, tracePath, templatePaths, spec)
	cmd := exec.CommandContext(ctx, r.nucleiPath, args...)
	// Run in its own process group so Cancel/timeout kills nuclei and any child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}

	// Nuclei writes its findings to stdout and its diagnostics + -stats-json to
	// stderr (verified for the pinned v3.11.0). We route ONLY stderr through
	// statsWriter: -stats-json lines drive live progress (#66), and the full
	// stderr stream is mirrored verbatim to a per-run log file (rawOut) as the
	// execution-log archive (#94) — so the log captures template-load warnings
	// and host errors. stdout (the findings) is sent to io.Discard: the findings
	// are already persisted via -output and pulled by the backend as raw.jsonl,
	// so capturing them here would only duplicate results into the execution log.
	// Best-effort: a log file we can't open just disables the archive for this
	// run; the scan itself is unaffected.
	var stderr cappedBuffer
	sw := &statsWriter{setProgress: j.setProgress, errOut: &stderr, rawOut: logw}
	cmd.Stderr = sw
	cmd.Stdout = io.Discard

	writeCommandLog(logw, "nuclei", r.nucleiPath, args)
	err = cmd.Run()
	sw.flush()
	// Release the handshake anchor after Nuclei exits. This is the last writer
	// when Nuclei failed before opening -trace-log, and therefore guarantees EOF.
	_ = traceAnchor.Close()
	var coverage coverageResult
	coverageTimer := time.NewTimer(coverageDrainTimeout)
	select {
	case coverage = <-coverageCh:
		if !coverageTimer.Stop() {
			<-coverageTimer.C
		}
	case <-coverageTimer.C:
		_ = traceReader.Close()
		coverage.Warning = fmt.Sprintf(
			"endpoint coverage unavailable: trace reducer did not finish within %s",
			coverageDrainTimeout,
		)
	}
	findingCount := countLines(j.resultsPath)
	coverage = validateCoverageAgainstFindings(coverage, findingCount)
	if coverage.Warning != "" {
		_, _ = fmt.Fprintf(logw, "[WRN] %s\n", coverage.Warning)
	}
	j.setCoverage(coverage.Endpoints, coverage.Warning)
	if err != nil {
		// A timeout is its own clean message: the OS reason (`signal: killed`) and
		// the stderr tail (a batch of per-host "Skipped … unresponsive" diagnostics)
		// only bury the cause. The full stderr is in the execution-log archive (#94).
		if ctx.Err() == context.DeadlineExceeded {
			j.fail(fmt.Errorf("nuclei: scan timed out after %s (see execution log for details)", timeout))
			return
		}
		// Nuclei exits 0 even when it finds nothing; a non-zero exit is a real
		// failure (bad flags, killed, etc.). Summarize the stderr tail so a burst of
		// repeated "Skipped … unresponsive" lines can't crowd out the real reason.
		msg := summarizeCapturedStderr(&stderr, 20)
		j.fail(fmt.Errorf("nuclei: %v: %s", err, msg))
		return
	}

	j.complete(findingCount)
}

func writeTargetsFile(path string, targets []string) error {
	return os.WriteFile(path, []byte(strings.Join(types.DeduplicateTargetHosts(targets), "\n")+"\n"), 0o640)
}

// buildArgs assembles the Nuclei command line from the spec.
func buildArgs(targetsFile, out, tracePath string, templatePaths []string, spec types.ScanSpec) []string {
	args := []string{
		"-list", targetsFile,
		"-jsonl",
		"-output", out,
		// Nuclei's structured request trace is the authoritative host-reachability
		// evidence for lifecycle mitigation (#91). It records both successful
		// requests and connection errors without duplicating response bodies.
		"-trace-log", tracePath,
		// Deliberately NOT -silent: that flag prints findings to stdout but
		// suppresses Nuclei's diagnostic logs (template-load warnings, host
		// errors) — the opposite of what the execution-log archive (#94) needs.
		// Without it, findings still go to -output (→ raw.jsonl) and stderr
		// carries the banner + [INF]/[WRN]/[ERR] logs + -stats-json, which is what
		// run() captures as the log. -no-color keeps that log free of ANSI codes.
		"-no-color",
		"-disable-update-check",
		// Emit periodic JSON progress stats (parsed for the live progress bar,
		// #66). Nuclei writes these to stderr, where statsWriter parses them.
		"-stats-json",
		"-stats-interval", "3",
	}
	for _, p := range templatePaths {
		args = append(args, "-templates", p)
	}
	if spec.Options.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(spec.Options.RateLimit))
	}
	if spec.Options.Concurrency > 0 {
		args = append(args, "-concurrency", strconv.Itoa(spec.Options.Concurrency))
	}
	// -max-host-error: raise it for fragile devices that trip Nuclei's default of
	// 30 on HTTP alone (which makes Nuclei abandon the host, silently skipping its
	// not-yet-run executors like the SSL/TLS pass). <= 0 leaves Nuclei's default.
	if spec.Options.MaxHostError > 0 {
		args = append(args, "-max-host-error", strconv.Itoa(spec.Options.MaxHostError))
	}
	return args
}

var versionRe = regexp.MustCompile(`v?\d+\.\d+\.\d+`)

// Capabilities reports the node's runtime facts for the backend's health poll
// (#98). TemplatesCommit is the digest of the active template bundle (#85), empty
// until the backend pushes one; the backend uses it to detect drift before a scan.
func (r *Runner) Capabilities() types.Capabilities {
	return types.Capabilities{
		NucleiVersion:   r.nucleiVersion(),
		TemplatesCommit: r.bundle.activeDigest(),
	}
}

// nucleiVersion returns the engine version string, or "" if it can't be read.
func (r *Runner) nucleiVersion() string {
	return r.nucleiVersionContext(context.Background())
}

func (r *Runner) nucleiVersionContext(parent context.Context) string {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.nucleiPath, "-version").CombinedOutput()
	if err != nil {
		return ""
	}
	return versionRe.FindString(string(out))
}

func (j *job) setVersion(v string) {
	j.mu.Lock()
	j.status.NucleiVersion = v
	j.mu.Unlock()
}

func (j *job) setCancel(c context.CancelFunc) {
	j.mu.Lock()
	j.cancel = c
	j.mu.Unlock()
}

// setProgress records the latest live progress snapshot (from Nuclei's
// -stats-json). A copy is stored so the status snapshot returned to callers is
// independent. The current phase is stamped on so the UI knows these are Nuclei
// (scanning) numbers, not discovery ones.
func (j *job) setProgress(p types.ScanProgress) {
	j.mu.Lock()
	prog := p
	prog.Phase = j.phase
	j.status.Progress = &prog
	j.mu.Unlock()
}

// setPhase records the current execution stage (#86). It is stamped onto every
// subsequent progress snapshot so callers can tell discovery from scanning.
func (j *job) setPhase(p types.ScanPhase) {
	j.mu.Lock()
	j.phase = p
	j.mu.Unlock()
}

// setDiscoveryProgress publishes the discovering-phase live tally (naabu),
// counted from naabu's "Found N ports on host" log lines. hosts is the number of
// hosts seen with at least one open port; ports is the running total of open
// ports found.
func (j *job) setDiscoveryProgress(hosts, ports int) {
	j.mu.Lock()
	j.status.Progress = &types.ScanProgress{
		Phase:     types.PhaseDiscovering,
		DiscHosts: hosts,
		DiscPorts: ports,
	}
	j.mu.Unlock()
}

// setDiscoveredTargets records the narrowed host:port list from the naabu
// pre-pass, reported to the backend for the scan's life.
func (j *job) setDiscoveredTargets(t []string) {
	j.mu.Lock()
	j.status.DiscoveredTargets = t
	j.mu.Unlock()
}

func (j *job) setCoverage(endpoints []types.EndpointCoverage, warning string) {
	j.mu.Lock()
	j.status.CoveredEndpoints = append([]types.EndpointCoverage{}, endpoints...)
	j.status.CoverageWarning = warning
	j.mu.Unlock()
}

func appendCoverageWarning(existing, warning string) string {
	if existing == "" {
		return warning
	}
	return existing + "; " + warning
}

func validateCoverageAgainstFindings(coverage coverageResult, findingCount int) coverageResult {
	if findingCount > 0 && coverage.Endpoints != nil && len(coverage.Endpoints) == 0 {
		coverage.Endpoints = nil
		coverage.Warning = appendCoverageWarning(coverage.Warning,
			fmt.Sprintf("endpoint coverage unavailable: scan produced %d findings but trace recorded no successful template/endpoint pairs", findingCount))
	}
	return coverage
}

func (j *job) fail(err error) {
	j.mu.Lock()
	j.status.State = types.ScanFailed
	j.status.Error = err.Error()
	j.mu.Unlock()
}

func (j *job) complete(count int) {
	j.mu.Lock()
	j.status.State = types.ScanComplete
	j.status.FindingCount = count
	j.mu.Unlock()
}

// countLines counts non-empty lines in the results file (== finding count).
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// skippedUnresponsiveRe matches Nuclei's per-host "Skipped … unresponsive"
// diagnostics (both the transient "found unresponsive N times" and the terminal
// "unresponsive permanently: cause=…" forms). On a scan of many host:port pairs
// these arrive as a long burst at the end.
var skippedUnresponsiveRe = regexp.MustCompile(`Skipped .* unresponsive`)

func summarizeCapturedStderr(stderr *cappedBuffer, n int) string {
	msg := strings.TrimSpace(summarizeStderr(stderr.String(), n))
	if !stderr.truncated {
		return msg
	}
	const marker = "[WRN] stderr tail truncated; see execution log for full output"
	if msg == "" {
		return marker
	}
	return msg + "\n" + marker
}

// summarizeStderr collapses runs of "Skipped … unresponsive" diagnostics into a
// single count line and returns the last n lines of the result — so the error
// string surfaced in the UI points at the actual cause instead of a wall of
// repeated skip diagnostics. The verbatim stderr is still in the execution-log
// archive (#94), so nothing is lost.
func summarizeStderr(s string, n int) string {
	var out []string
	skipped := 0
	flush := func() {
		if skipped > 0 {
			noun := "targets"
			if skipped == 1 {
				noun = "target"
			}
			out = append(out, fmt.Sprintf("[INF] Skipped %d %s as unresponsive", skipped, noun))
			skipped = 0
		}
	}
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if skippedUnresponsiveRe.MatchString(l) {
			skipped++
			continue
		}
		flush()
		out = append(out, l)
	}
	flush()
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return strings.Join(out, "\n")
}
