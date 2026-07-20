package scanner

import (
	"slices"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestBuildArgs(t *testing.T) {
	spec := types.ScanSpec{
		Targets: []string{"scanme.sh"},
		Templates: types.TemplateSelector{
			Severities: []string{"critical", "high"},
			Tags:       []string{"cve"},
		},
		Options: types.ScanOptions{RateLimit: 150, Concurrency: 25, MaxHostError: 50},
	}
	args := buildArgs("/t/targets.txt", "/t/out.jsonl", spec)

	mustHavePair := func(flag, val string) {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == flag && args[i+1] == val {
				return
			}
		}
		t.Errorf("expected %s %s in args: %v", flag, val, args)
	}
	mustHavePair("-list", "/t/targets.txt")
	mustHavePair("-output", "/t/out.jsonl")
	mustHavePair("-severity", "critical")
	mustHavePair("-severity", "high")
	mustHavePair("-tags", "cve")
	mustHavePair("-rate-limit", "150")
	mustHavePair("-concurrency", "25")
	mustHavePair("-max-host-error", "50")
	if !slices.Contains(args, "-jsonl") {
		t.Errorf("expected -jsonl in args: %v", args)
	}
	// The execution-log archive (#94) captures Nuclei's stderr, which -silent
	// would strip of diagnostics (while still leaking findings to the captured
	// stream). It must stay off; -no-color keeps the log ANSI-free.
	if slices.Contains(args, "-silent") {
		t.Errorf("-silent must not be set (it suppresses diagnostics from the log): %v", args)
	}
	if !slices.Contains(args, "-no-color") {
		t.Errorf("expected -no-color in args: %v", args)
	}
	if !slices.Contains(args, "-stats-json") {
		t.Errorf("expected -stats-json in args: %v", args)
	}
}

func TestBuildArgsMinimal(t *testing.T) {
	// No filters/options => no severity/tags/rate flags, but core flags present.
	args := buildArgs("/t/targets.txt", "/t/out.jsonl", types.ScanSpec{Targets: []string{"x"}})
	if slices.Contains(args, "-rate-limit") || slices.Contains(args, "-severity") ||
		slices.Contains(args, "-max-host-error") {
		t.Errorf("unexpected optional flags in minimal args: %v", args)
	}
	if !slices.Contains(args, "-jsonl") {
		t.Errorf("expected -jsonl in args: %v", args)
	}
}
