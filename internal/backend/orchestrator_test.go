package backend

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestScanFindingLines(t *testing.T) {
	line := `{"template-id":"t","host":"h"}`

	// Happy path: three valid lines, one blank, one unparseable.
	in := line + "\n\nnot-json\n" + line + "\n" + line + "\n"
	var got int
	n, skipped, err := scanFindingLines(strings.NewReader(in), 1<<20, 100,
		func(types.NucleiFinding, []byte) error { got++; return nil })
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n != 3 || got != 3 {
		t.Errorf("ingested = %d (emit called %d), want 3", n, got)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the not-json line)", skipped)
	}
}

func TestScanFindingLinesCountCap(t *testing.T) {
	line := `{"template-id":"t","host":"h"}` + "\n"
	in := strings.Repeat(line, 10)
	n, _, err := scanFindingLines(strings.NewReader(in), 1<<20, 3,
		func(types.NucleiFinding, []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "finding cap") {
		t.Fatalf("err = %v, want finding-cap error", err)
	}
	if n != 3 {
		t.Errorf("ingested = %d, want exactly the cap (3)", n)
	}
}

func TestScanFindingLinesByteCap(t *testing.T) {
	// A stream longer than the byte cap must abort with a byte-cap error rather
	// than silently truncating.
	in := strings.Repeat(`{"template-id":"t","host":"h"}`+"\n", 100)
	_, _, err := scanFindingLines(strings.NewReader(in), 50, 100_000,
		func(types.NucleiFinding, []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "byte cap") {
		t.Fatalf("err = %v, want byte-cap error", err)
	}
}

func TestScanFindingLinesEmitError(t *testing.T) {
	line := `{"template-id":"t","host":"h"}` + "\n"
	sentinel := errors.New("db down")
	_, _, err := scanFindingLines(strings.NewReader(line), 1<<20, 100,
		func(types.NucleiFinding, []byte) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the emit error propagated", err)
	}
}

func TestScanFindingLinesSkipsRecordLocalErrors(t *testing.T) {
	line := `{"template-id":"t","host":"h"}` + "\n"
	sentinel := errors.New("invalid source record")
	recordErr := store.NewFindingRecordError("raw JSON projection", sentinel)
	var calls int
	n, skipped, details, err := scanFindingLinesWithDetails(strings.NewReader(line+line), 1<<20, 100,
		func(types.NucleiFinding, []byte) error {
			calls++
			if calls == 1 {
				return recordErr
			}
			return nil
		})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n != 1 || skipped != 1 {
		t.Fatalf("ingested=%d skipped=%d, want 1 and 1", n, skipped)
	}
	if len(details) != 1 || !strings.Contains(details[0], "line 1") || !strings.Contains(details[0], "raw JSON projection") {
		t.Fatalf("details=%v, want bounded line/stage detail", details)
	}
	if !errors.Is(recordErr, sentinel) {
		t.Errorf("record error does not unwrap to the source error: %v", recordErr)
	}
}

func TestRetryWriteSucceedsAfterTransientErrors(t *testing.T) {
	var calls int
	err := retryWrite(context.Background(), 5, time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (stop retrying on first success)", calls)
	}
}

func TestRetryWriteExhaustsAttempts(t *testing.T) {
	sentinel := errors.New("db down")
	var calls int
	err := retryWrite(context.Background(), 3, time.Millisecond, func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the last error returned", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want exactly 3 (the attempts cap)", calls)
	}
}

func TestRetryWriteStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	err := retryWrite(ctx, 5, 50*time.Millisecond, func() error {
		calls++
		if calls == 1 {
			cancel()
		}
		return errors.New("still down")
	})
	if err == nil {
		t.Fatal("err = nil, want the underlying error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (cancel should stop further retries)", calls)
	}
}

func TestNodeRuntimeBudget(t *testing.T) {
	min := time.Minute
	ptrDisc := func(enabled bool, sec int) *types.DiscoveryOptions {
		return &types.DiscoveryOptions{Enabled: enabled, TimeoutSec: sec}
	}
	cases := []struct {
		name string
		spec types.ScanSpec
		want time.Duration
	}{
		{
			// The scan that hit the old fixed 30m budget: Nuclei 600s + discovery 1200s.
			// The node can run 30m here, so the budget must be at least that.
			name: "discovery plus nuclei sum",
			spec: types.ScanSpec{Options: types.ScanOptions{TimeoutSec: 600, Discovery: ptrDisc(true, 1200)}},
			want: 30 * min,
		},
		{
			name: "discovery disabled => nuclei only",
			spec: types.ScanSpec{Options: types.ScanOptions{TimeoutSec: 600, Discovery: ptrDisc(false, 1200)}},
			want: 10 * min,
		},
		{
			name: "no discovery block => nuclei only",
			spec: types.ScanSpec{Options: types.ScanOptions{TimeoutSec: 600}},
			want: 10 * min,
		},
		{
			// Zero timeouts fall back to the node's own defaults (30m + 5m).
			name: "zero timeouts use node defaults",
			spec: types.ScanSpec{Options: types.ScanOptions{Discovery: ptrDisc(true, 0)}},
			want: 35 * min,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeRuntimeBudget(tc.spec); got != tc.want {
				t.Errorf("nodeRuntimeBudget = %s, want %s", got, tc.want)
			}
		})
	}
	// The full poll budget must exceed the node's own runtime so the node's specific
	// timeout error wins over the generic poll-budget give-up.
	spec := types.ScanSpec{Options: types.ScanOptions{TimeoutSec: 600, Discovery: ptrDisc(true, 1200)}}
	if pollWait := nodeRuntimeBudget(spec) + nodeOverhead; pollWait <= nodeRuntimeBudget(spec) {
		t.Errorf("poll budget %s must exceed node runtime %s", pollWait, nodeRuntimeBudget(spec))
	}
}
