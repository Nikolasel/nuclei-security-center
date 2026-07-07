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
		Options: types.ScanOptions{RateLimit: 150, Concurrency: 25},
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
	if !slices.Contains(args, "-jsonl") {
		t.Errorf("expected -jsonl in args: %v", args)
	}
}

func TestBuildArgsMinimal(t *testing.T) {
	// No filters/options => no severity/tags/rate flags, but core flags present.
	args := buildArgs("/t/targets.txt", "/t/out.jsonl", types.ScanSpec{Targets: []string{"x"}})
	if slices.Contains(args, "-rate-limit") || slices.Contains(args, "-severity") {
		t.Errorf("unexpected optional flags in minimal args: %v", args)
	}
	if !slices.Contains(args, "-jsonl") {
		t.Errorf("expected -jsonl in args: %v", args)
	}
}
