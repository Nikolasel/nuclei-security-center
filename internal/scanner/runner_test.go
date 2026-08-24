package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestBuildArgs(t *testing.T) {
	spec := types.ScanSpec{
		Targets: []string{"scanme.sh"},
		Templates: types.TemplateSelector{
			TemplateIDs:     []string{"a", "b"},
			TemplatesCommit: "catalog-digest",
		},
		Options: types.ScanOptions{RateLimit: 150, Concurrency: 25, MaxHostError: 50},
	}
	args := buildArgs("/t/targets.txt", "/t/out.jsonl", "/t/trace.jsonl", []string{"/bundle/a.yaml", "/bundle/b.yaml"}, spec)

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
	mustHavePair("-trace-log", "/t/trace.jsonl")
	mustHavePair("-templates", "/bundle/a.yaml")
	mustHavePair("-templates", "/bundle/b.yaml")
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
	for _, legacy := range []string{"-severity", "-tags"} {
		if slices.Contains(args, legacy) {
			t.Errorf("legacy selector %q must not reach nuclei: %v", legacy, args)
		}
	}
}

func TestBuildArgsMinimal(t *testing.T) {
	// No filters/options => no severity/tags/rate flags, but core flags present.
	args := buildArgs("/t/targets.txt", "/t/out.jsonl", "/t/trace.jsonl", nil, types.ScanSpec{Targets: []string{"x"}})
	if slices.Contains(args, "-rate-limit") || slices.Contains(args, "-severity") ||
		slices.Contains(args, "-max-host-error") || slices.Contains(args, "-response-size-read") || slices.Contains(args, "-response-size-save") {
		t.Errorf("unexpected optional flags in minimal args: %v", args)
	}
	if !slices.Contains(args, "-jsonl") {
		t.Errorf("expected -jsonl in args: %v", args)
	}
}

func TestBuildArgsResponseSize(t *testing.T) {
	// Response-size caps (#274) emit nuclei's -response-size-read/-save and
	// are omitted when <=0 (nuclei default).
	for _, tc := range []struct {
		name string
		opts types.ScanOptions
		want []string
	}{
		{
			name: "both caps",
			opts: types.ScanOptions{ResponseSizeRead: 1048576, ResponseSizeSave: 524288},
			want: []string{"-response-size-read", "1048576", "-response-size-save", "524288"},
		},
		{
			name: "only read",
			opts: types.ScanOptions{ResponseSizeRead: 2097152},
			want: []string{"-response-size-read", "2097152"},
		},
		{
			name: "zero omitted",
			opts: types.ScanOptions{ResponseSizeRead: 0, ResponseSizeSave: 0},
			want: nil,
		},
		{
			name: "negative omitted",
			opts: types.ScanOptions{ResponseSizeRead: -1},
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := buildArgs("/t/targets.txt", "/t/out.jsonl", "/t/trace.jsonl", nil, types.ScanSpec{Targets: []string{"x"}, Options: tc.opts})
			for i := 0; i < len(tc.want); i += 2 {
				flag, val := tc.want[i], tc.want[i+1]
				found := false
				for j := 0; j+1 < len(args); j++ {
					if args[j] == flag && args[j+1] == val {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected %s %s in args %v", flag, val, args)
				}
			}
			// Zero/negative case must not emit the flag names at all.
			if tc.want == nil {
				for _, flag := range []string{"-response-size-read", "-response-size-save"} {
					if slices.Contains(args, flag) {
						t.Errorf("unexpected %s in args %v", flag, args)
					}
				}
			}
		})
	}
}

func TestWriteTargetsFileDeduplicatesAndPreservesURLPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	targets := []string{
		"Example.COM",
		"example.com",
		"https://EXAMPLE.com/AdminPanel",
		"https://example.com/AdminPanel",
		"https://example.com/adminpanel",
		"10.0.0.0/24",
		"10.0.0.0/24",
	}
	if err := writeTargetsFile(path, targets); err != nil {
		t.Fatalf("writeTargetsFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read targets file: %v", err)
	}
	want := "example.com\nhttps://example.com/AdminPanel\nhttps://example.com/adminpanel\n10.0.0.0/24\n"
	if string(got) != want {
		t.Errorf("targets file = %q, want %q", got, want)
	}
}

func TestSummarizeStderr(t *testing.T) {
	// A burst of per-host "Skipped … unresponsive" diagnostics (both the transient
	// and permanent forms) collapses to a single count line, so the real cause isn't
	// crowded out of the tail.
	in := strings.Join([]string{
		"[INF] Using Interactsh Server: oast.site",
		`[INF] Skipped 192.168.178.1:21 from target list as found unresponsive 32 times`,
		`[INF] Skipped 192.168.178.1:5060 from target list as found unresponsive permanently: cause="i/o timeout"`,
		`[INF] Skipped 192.168.178.33:5432 from target list as found unresponsive permanently: cause="i/o timeout"`,
		"[FTL] could not run nuclei: something fatal",
	}, "\n")
	got := summarizeStderr(in, 20)
	if strings.Count(got, "Skipped") != 1 {
		t.Errorf("expected the skip burst collapsed to one line, got:\n%s", got)
	}
	if !strings.Contains(got, "Skipped 3 targets as unresponsive") {
		t.Errorf("expected a 3-target summary, got:\n%s", got)
	}
	// The non-skip lines survive, including the actual fatal reason.
	for _, want := range []string{"Interactsh Server", "something fatal"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q retained, got:\n%s", want, got)
		}
	}
	// Tail limit still applies after collapsing.
	if got := summarizeStderr("a\nb\nc\nd\ne", 2); got != "d\ne" {
		t.Errorf("last-n after summarize = %q, want %q", got, "d\ne")
	}
}

func TestSummarizeCapturedStderrMarksTruncatedTail(t *testing.T) {
	var stderr cappedBuffer
	input := strings.Repeat("[ERR] noisy diagnostic\n", maxCapturedOutput/len("[ERR] noisy diagnostic\n")+1)
	_, _ = stderr.Write([]byte(input))

	got := summarizeCapturedStderr(&stderr, 20)
	if !strings.Contains(got, "stderr tail truncated; see execution log for full output") {
		t.Fatalf("summary = %q, want truncation marker", got)
	}
}
