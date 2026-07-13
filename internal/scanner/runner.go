// Package scanner is the credential-less execution engine. It runs the Nuclei
// binary against a ScanSpec and serves the results back over HTTP. It holds no
// database access and initiates no connection back to the backend.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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
	workRoot   string

	mu    sync.Mutex
	scans map[string]*job
}

type job struct {
	mu          sync.Mutex
	status      types.ScanStatus
	resultsPath string
	cancel      context.CancelFunc
}

// NewRunner prepares a Runner. workRoot is where per-scan temp dirs live.
func NewRunner(nucleiPath, workRoot string) (*Runner, error) {
	if err := os.MkdirAll(workRoot, 0o750); err != nil {
		return nil, fmt.Errorf("create work root: %w", err)
	}
	return &Runner{
		nucleiPath: nucleiPath,
		workRoot:   workRoot,
		scans:      make(map[string]*job),
	}, nil
}

// Start launches a scan asynchronously and returns its node-local id. The scan
// runs in its own goroutine; callers poll Status and read Results.
func (r *Runner) Start(spec types.ScanSpec) (string, error) {
	if len(spec.Targets) == 0 {
		return "", fmt.Errorf("scan spec has no targets")
	}
	id := types.NewID()
	dir := filepath.Join(r.workRoot, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create scan dir: %w", err)
	}

	j := &job{
		status:      types.ScanStatus{ID: id, State: types.ScanRunning},
		resultsPath: filepath.Join(dir, "results.jsonl"),
	}
	r.mu.Lock()
	r.scans[id] = j
	r.mu.Unlock()

	go r.run(j, spec, dir)
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

func (r *Runner) run(j *job, spec types.ScanSpec, dir string) {
	// Best-effort template sync + version capture before the scan, so the
	// backend can record exactly what ran (reproducibility / audit).
	r.syncTemplates()
	version := r.nucleiVersion()
	j.setVersion(version)

	timeout := time.Duration(spec.Options.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	j.setCancel(cancel)
	defer cancel()

	targetsFile := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetsFile, []byte(strings.Join(spec.Targets, "\n")+"\n"), 0o640); err != nil {
		j.fail(fmt.Errorf("write targets file: %w", err))
		return
	}

	args := buildArgs(targetsFile, j.resultsPath, spec)
	cmd := exec.CommandContext(ctx, r.nucleiPath, args...)
	// Run in its own process group so Cancel/timeout kills nuclei and any child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}

	// Route Nuclei's stderr/stdout through statsWriter: -stats-json lines update
	// live progress, everything else is captured for failure reporting. Both
	// streams share one writer (mutex-serialized) so stats land wherever Nuclei
	// emits them across versions.
	var stderr bytes.Buffer
	sw := &statsWriter{setProgress: j.setProgress, errOut: &stderr}
	cmd.Stderr = sw
	cmd.Stdout = sw

	err := cmd.Run()
	sw.flush()
	if err != nil {
		// Nuclei exits 0 even when it finds nothing; a non-zero exit is a real
		// failure (bad flags, killed, etc.).
		msg := strings.TrimSpace(lastLines(stderr.String(), 5))
		if ctx.Err() == context.DeadlineExceeded {
			msg = "scan timed out: " + msg
		}
		j.fail(fmt.Errorf("nuclei: %v: %s", err, msg))
		return
	}

	count := countLines(j.resultsPath)
	j.complete(count)
}

// buildArgs assembles the Nuclei command line from the spec.
func buildArgs(targetsFile, out string, spec types.ScanSpec) []string {
	args := []string{
		"-list", targetsFile,
		"-jsonl",
		"-output", out,
		"-silent", // suppress banner/progress noise on stdout
		"-disable-update-check",
		// Emit periodic JSON progress stats (parsed for the live progress bar,
		// #66). Findings still go to -output; stats go to stderr/stdout where
		// statsWriter separates them from error output.
		"-stats-json",
		"-stats-interval", "3",
	}
	for _, s := range spec.Templates.Severities {
		args = append(args, "-severity", s)
	}
	for _, t := range spec.Templates.Tags {
		args = append(args, "-tags", t)
	}
	for _, p := range spec.Templates.Paths {
		args = append(args, "-templates", p)
	}
	if spec.Options.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(spec.Options.RateLimit))
	}
	if spec.Options.Concurrency > 0 {
		args = append(args, "-concurrency", strconv.Itoa(spec.Options.Concurrency))
	}
	return args
}

// syncTemplates installs/updates the community template set before a scan.
// NOTE: we must NOT pass -disable-update-check here — that flag suppresses the
// template install itself, so on a fresh node templates never land and the scan
// aborts with "no templates provided for scan". Best-effort otherwise: once
// templates exist, a failed refresh (e.g. offline) should not block scanning.
func (r *Runner) syncTemplates() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.nucleiPath, "-update-templates")
	_ = cmd.Run()
}

// NucleiVersion returns the engine version string (best-effort), for the node
// registry's capability reporting (#22).
func (r *Runner) NucleiVersion() string { return r.nucleiVersion() }

var versionRe = regexp.MustCompile(`v?\d+\.\d+\.\d+`)

// nucleiVersion returns the engine version string, or "" if it can't be read.
func (r *Runner) nucleiVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

// setProgress records the latest live progress snapshot (from -stats-json). A
// copy is stored so the status snapshot returned to callers is independent.
func (j *job) setProgress(p types.ScanProgress) {
	j.mu.Lock()
	prog := p
	j.status.Progress = &prog
	j.mu.Unlock()
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
