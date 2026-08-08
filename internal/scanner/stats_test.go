package scanner

import (
	"bytes"
	"sync"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestParseNucleiStatsStringNumbers(t *testing.T) {
	// Nuclei's clistats commonly encodes the numbers as JSON strings.
	line := []byte(`{"duration":"0:00:12","errors":"0","hosts":"2","matched":"3","percent":"45","requests":"450","rps":"37","templates":"1000","total":"1000"}`)
	p, ok := parseNucleiStats(line)
	if !ok {
		t.Fatal("expected a stats line")
	}
	if p.Percent != 45 || p.Requests != 450 || p.Total != 1000 || p.Hosts != 2 || p.RPS != 37 || p.Matched != 3 {
		t.Fatalf("parsed wrong: %+v", p)
	}
}

func TestParseNucleiStatsPlainNumbers(t *testing.T) {
	// Other versions emit plain JSON numbers.
	line := []byte(`{"percent":50.5,"requests":500,"total":1000,"hosts":1}`)
	p, ok := parseNucleiStats(line)
	if !ok {
		t.Fatal("expected a stats line")
	}
	if p.Percent != 50.5 || p.Requests != 500 || p.Total != 1000 {
		t.Fatalf("parsed wrong: %+v", p)
	}
}

func TestParseNucleiStatsNotStats(t *testing.T) {
	for _, line := range []string{
		``,
		`[INF] Running nuclei on 2 hosts`,
		`{"template-id":"x","host":"h"}`, // a finding line, not stats (no total/percent)
		`not json at all`,
		`{"percent":"10"}`, // missing total
	} {
		if _, ok := parseNucleiStats([]byte(line)); ok {
			t.Errorf("line %q wrongly parsed as stats", line)
		}
	}
}

func TestStatsWriterSeparatesStatsFromErrors(t *testing.T) {
	var errBuf bytes.Buffer
	var mu sync.Mutex
	var last *types.ScanProgress
	sw := &statsWriter{
		setProgress: func(p types.ScanProgress) {
			mu.Lock()
			prog := p
			last = &prog
			mu.Unlock()
		},
		errOut: &errBuf,
	}

	// Interleave an error line, a stats line, and a partial line (no newline).
	sw.Write([]byte("[FTL] boom\n"))
	sw.Write([]byte(`{"percent":"75","total":"1000","requests":"750"}` + "\n"))
	sw.Write([]byte("trailing without newline"))
	sw.flush()

	if last == nil || last.Percent != 75 {
		t.Fatalf("progress not captured: %+v", last)
	}
	got := errBuf.String()
	if got != "[FTL] boom\ntrailing without newline\n" {
		t.Fatalf("error output = %q", got)
	}
}

// The rawOut mirror (#94) must capture the full byte stream verbatim — stats
// lines included — so the archived execution log is exactly what Nuclei emitted,
// even as errOut still filters stats out of the failure-report buffer.
func TestStatsWriterMirrorsRawOut(t *testing.T) {
	var errBuf, rawBuf bytes.Buffer
	sw := &statsWriter{errOut: &errBuf, rawOut: &rawBuf}

	sw.Write([]byte("[INF] loading templates\n"))
	sw.Write([]byte(`{"percent":"50","total":"10","requests":"5"}` + "\n"))
	sw.Write([]byte("[ERR] host down"))
	sw.flush()

	want := "[INF] loading templates\n" + `{"percent":"50","total":"10","requests":"5"}` + "\n" + "[ERR] host down"
	if got := rawBuf.String(); got != want {
		t.Fatalf("rawOut = %q, want %q", got, want)
	}
	// errOut still excludes the stats line.
	if got := errBuf.String(); got != "[INF] loading templates\n[ERR] host down\n" {
		t.Fatalf("errOut = %q", got)
	}
}

func TestStatsWriterBoundsUnterminatedDiagnosticAndErrorTail(t *testing.T) {
	var errOut cappedBuffer
	var rawOut bytes.Buffer
	sw := &statsWriter{errOut: &errOut, rawOut: &rawOut}

	input := append(bytes.Repeat([]byte{'x'}, maxCapturedOutput), []byte("tail-marker")...)
	if _, err := sw.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := len(sw.buf); got > maxCapturedOutput {
		t.Fatalf("pending line length = %d, want <= %d", got, maxCapturedOutput)
	}
	sw.flush()

	if got := rawOut.Bytes(); !bytes.Equal(got, input) {
		t.Fatalf("rawOut length = %d, want %d-byte verbatim stream", len(got), len(input))
	}
	if got := len(errOut.String()); got > maxCapturedOutput {
		t.Fatalf("errOut length = %d, want <= %d", got, maxCapturedOutput)
	}
	if !bytes.HasSuffix(errOut.buf.Bytes(), []byte("tail-marker\n")) {
		t.Fatalf("errOut did not retain the diagnostic tail: %q", errOut.String())
	}
}
