package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

const (
	// Deliberately shared by template validation, scan diagnostics, and stats
	// framing so every subprocess diagnostic path has the same bounded tail.
	maxCapturedOutput   = 64 << 10 // 64 KiB retained tail for subprocess diagnostics
	maxValidationErrors = 20
	maxValidationLine   = 1024
)

// ValidateTemplate asks the node's pinned Nuclei binary to parse and validate
// one custom template without supplying a target. A normal non-zero Nuclei exit
// is an invalid-template verdict; context cancellation and process-launch
// failures are infrastructure errors.
func (r *Runner) ValidateTemplate(ctx context.Context, yaml []byte) (types.TemplateValidationResult, error) {
	result := types.TemplateValidationResult{Errors: []string{}}
	version := r.nucleiVersionContext(ctx)
	if version == "" {
		if ctx.Err() != nil {
			return result, fmt.Errorf("read nuclei version: %w", ctx.Err())
		}
		return result, errors.New("read nuclei version")
	}
	result.NucleiVersion = version

	dir, err := os.MkdirTemp(r.workRoot, "template-validation-*")
	if err != nil {
		return result, fmt.Errorf("create template validation dir: %w", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		return result, fmt.Errorf("write template for validation: %w", err)
	}

	args := []string{"-validate", "-templates", path, "-no-color", "-disable-update-check"}
	cmd := exec.CommandContext(ctx, r.nucleiPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	var output cappedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err = cmd.Run()
	if err == nil {
		result.Valid = true
		return result, nil
	}
	if ctx.Err() != nil {
		return result, fmt.Errorf("validate template: %w", ctx.Err())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return result, fmt.Errorf("run nuclei validation: %w", err)
	}

	result.Errors = validationDiagnostics(output.String(), path)
	if len(result.Errors) == 0 {
		result.Errors = []string{"Nuclei rejected the template"}
	}
	return result, nil
}

// cappedBuffer accepts the complete process stream while retaining only a
// bounded tail. Nuclei's actionable fatal diagnostic is normally at the end.
type cappedBuffer struct {
	buf       []byte
	start     int
	length    int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if original == 0 {
		return 0, nil
	}
	if len(b.buf) == 0 {
		b.buf = make([]byte, maxCapturedOutput)
	}
	if original >= maxCapturedOutput {
		if original > maxCapturedOutput || b.length > 0 {
			b.truncated = true
		}
		copy(b.buf, p[original-maxCapturedOutput:])
		b.start = 0
		b.length = maxCapturedOutput
		return original, nil
	}
	overflow := b.length + original - maxCapturedOutput
	if overflow > 0 {
		b.start = (b.start + overflow) % maxCapturedOutput
		b.length -= overflow
		b.truncated = true
	}
	index := (b.start + b.length) % maxCapturedOutput
	first := len(b.buf) - index
	if first > len(p) {
		first = len(p)
	}
	copy(b.buf[index:index+first], p[:first])
	if first < len(p) {
		copy(b.buf[:len(p)-first], p[first:])
	}
	b.length += len(p)
	return original, nil
}

func (b *cappedBuffer) String() string {
	if b.length == 0 {
		return ""
	}
	out := make([]byte, b.length)
	first := len(b.buf) - b.start
	if first > b.length {
		first = b.length
	}
	copy(out, b.buf[b.start:b.start+first])
	copy(out[first:], b.buf[:b.length-first])
	return string(out)
}

func validationDiagnostics(output, templatePath string) []string {
	lines := actionableValidationLines(output)
	out := make([]string, 0, len(lines))
	templateDir := filepath.Dir(templatePath)
	for _, line := range lines {
		line = strings.ReplaceAll(line, templatePath, "template.yaml")
		line = sanitizeValidationLine(line, templateDir)
		out = append(out, line)
	}
	if len(out) > maxValidationErrors {
		out = out[len(out)-maxValidationErrors:]
	}
	return out
}

func sanitizeValidationLine(line, validationDir string) string {
	line = strings.ReplaceAll(line, validationDir, "<validation-dir>")
	if len(line) > maxValidationLine {
		line = line[:maxValidationLine]
		for !utf8.ValidString(line) {
			line = line[:len(line)-1]
		}
	}
	return line
}

var _ io.Writer = (*cappedBuffer)(nil)
