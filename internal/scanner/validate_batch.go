package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

const maxBatchDiagnosticLines = 100

// ValidateTemplateBundle verifies a transient template bundle using the same
// manifest/hash rules as an activatable catalog bundle, then validates every
// template in one Nuclei process. The bundle is never activated and is removed
// before return.
func (r *Runner) ValidateTemplateBundle(ctx context.Context, body io.Reader) (types.TemplateBatchValidationResult, error) {
	result := types.TemplateBatchValidationResult{
		Failures: []types.TemplateValidationFailure{},
		Errors:   []string{},
	}

	dir, err := os.MkdirTemp(r.workRoot, "template-batch-validation-*")
	if err != nil {
		return result, fmt.Errorf("create batch validation dir: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := extractTarGz(body, dir); err != nil {
		return result, err
	}
	manifest, err := readManifest(dir)
	if err != nil {
		return result, err
	}
	if err := verifyManifest(dir, manifest); err != nil {
		return result, err
	}
	for _, entry := range manifest.Templates {
		clean := filepath.ToSlash(filepath.Clean(entry.Path))
		if !strings.HasPrefix(clean, "custom/") {
			return result, fmt.Errorf(
				"%w: batch template %q is outside the custom subtree",
				ErrInvalidBundle, entry.ID,
			)
		}
	}

	version := r.nucleiVersionContext(ctx)
	if version == "" {
		if ctx.Err() != nil {
			return result, fmt.Errorf("read nuclei version: %w", ctx.Err())
		}
		return result, errors.New("read nuclei version")
	}
	result.NucleiVersion = version

	args := []string{
		"-validate", "-templates", filepath.Join(dir, "custom"),
		"-no-color", "-disable-update-check",
	}
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
		return result, fmt.Errorf("validate template batch: %w", ctx.Err())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return result, fmt.Errorf("run nuclei batch validation: %w", err)
	}

	result.Failures, result.Errors, result.Truncated = batchValidationDiagnostics(
		output.String(), output.truncated, dir, manifest,
	)
	if len(result.Failures) == 0 && len(result.Errors) == 0 {
		result.Errors = []string{"Nuclei rejected the template batch"}
	}
	return result, nil
}

func batchValidationDiagnostics(
	output string,
	outputTruncated bool,
	dir string,
	manifest types.TemplateBundleManifest,
) ([]types.TemplateValidationFailure, []string, bool) {
	lines := actionableValidationLines(output)
	truncated := outputTruncated
	if len(lines) > maxBatchDiagnosticLines {
		lines = lines[len(lines)-maxBatchDiagnosticLines:]
		truncated = true
	}

	type templatePath struct {
		id   string
		path string
	}
	paths := make([]templatePath, 0, len(manifest.Templates))
	for _, entry := range manifest.Templates {
		absolute, err := safeJoin(dir, entry.Path)
		if err == nil {
			paths = append(paths, templatePath{id: entry.ID, path: absolute})
		}
	}
	// A longer path first avoids a theoretical prefix match when catalog paths
	// share a stem.
	sort.Slice(paths, func(i, j int) bool { return len(paths[i].path) > len(paths[j].path) })

	byID := make(map[string][]string)
	var global []string
	for _, line := range lines {
		matched := ""
		for _, candidate := range paths {
			if strings.Contains(line, candidate.path) {
				matched = candidate.id
				line = strings.ReplaceAll(line, candidate.path, "template.yaml")
				break
			}
		}
		line = sanitizeValidationLine(line, dir)
		if matched == "" {
			global = appendUnique(global, line)
			continue
		}
		byID[matched] = appendUnique(byID[matched], line)
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	failures := make([]types.TemplateValidationFailure, 0, len(ids))
	for _, id := range ids {
		failures = append(failures, types.TemplateValidationFailure{
			TemplateID: id,
			Errors:     byID[id],
		})
	}
	return failures, global, truncated
}

func actionableValidationLines(output string) []string {
	var all, actionable []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		all = append(all, line)
		if strings.HasPrefix(line, "[ERR]") || strings.HasPrefix(line, "[FTL]") {
			actionable = append(actionable, line)
		}
	}
	if len(actionable) > 0 {
		return actionable
	}
	return all
}

func appendUnique(lines []string, line string) []string {
	for _, existing := range lines {
		if existing == line {
			return lines
		}
	}
	return append(lines, line)
}
