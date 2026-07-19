package scanner

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"sync"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Nuclei progress stats (#66). Run with -stats-json -stats-interval N, Nuclei
// periodically emits a small JSON object describing progress (percent complete,
// requests done/total, hosts, rps, matches). We parse the latest one to surface
// a progress bar. Nuclei's clistats encodes these numbers as JSON *strings* in
// most versions but plain numbers in others, so parsing is deliberately lenient
// (numAny handles both) and any line that isn't a stats object is treated as
// ordinary output — so this never corrupts error reporting if the format shifts.

// parseNucleiStats parses one line as a Nuclei stats object. ok is false when
// the line isn't stats (e.g. a log/error line), so the caller routes it
// elsewhere. A stats line is identified by carrying both "total" and "percent".
func parseNucleiStats(line []byte) (types.ScanProgress, bool) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return types.ScanProgress{}, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return types.ScanProgress{}, false
	}
	if _, ok := raw["total"]; !ok {
		return types.ScanProgress{}, false
	}
	if _, ok := raw["percent"]; !ok {
		return types.ScanProgress{}, false
	}
	p := types.ScanProgress{
		Percent:  numAny(raw["percent"]),
		Requests: int64(numAny(raw["requests"])),
		Total:    int64(numAny(raw["total"])),
		Hosts:    int64(numAny(raw["hosts"])),
		RPS:      int64(numAny(raw["rps"])),
		Matched:  int64(numAny(raw["matched"])),
	}
	return p, true
}

// numAny coerces a JSON value that may be a number or a numeric string to a
// float. Unparseable or absent values yield 0.
func numAny(raw json.RawMessage) float64 {
	if len(raw) == 0 {
		return 0
	}
	// Try a bare number first, then a quoted string.
	if f, err := strconv.ParseFloat(string(raw), 64); err == nil {
		return f
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return 0
}

// statsWriter is an io.Writer for Nuclei's stderr/stdout. It splits the stream
// into lines: stats-JSON lines update the job's live progress; every other line
// is forwarded to errOut (so genuine error output is still captured for failure
// reporting). When rawOut is set, the full byte stream is also mirrored to it
// verbatim (the per-run execution-log archive, #94) — stats lines included.
// Nuclei's stdout and stderr are copied by separate goroutines, so writes are
// serialized with a mutex.
type statsWriter struct {
	setProgress func(types.ScanProgress)
	errOut      *bytes.Buffer
	rawOut      io.Writer // nil disables the verbatim log mirror

	mu  sync.Mutex
	buf []byte
}

func (w *statsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.rawOut != nil {
		// Best-effort verbatim mirror; a log-file write error must not disrupt
		// the scan (we still return len(p) so the pipe copy keeps flowing).
		_, _ = w.rawOut.Write(p)
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

// flush handles any trailing partial line (no terminating newline) at scan end.
func (w *statsWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.handleLine(w.buf)
		w.buf = nil
	}
}

func (w *statsWriter) handleLine(line []byte) {
	if prog, ok := parseNucleiStats(line); ok {
		if w.setProgress != nil {
			w.setProgress(prog)
		}
		return
	}
	if w.errOut != nil {
		w.errOut.Write(line)
		w.errOut.WriteByte('\n')
	}
}
