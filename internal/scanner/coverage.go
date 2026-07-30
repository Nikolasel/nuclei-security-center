package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

const (
	maxCoverageTraceLine = 1024 * 1024
	maxCoveredHosts      = 100_000
)

type nucleiTraceEvent struct {
	Input string  `json:"input"`
	Error *string `json:"error"`
}

// coveredHostsFromTrace extracts host-level positive coverage from Nuclei's
// -trace-log JSONL. Only error-free requests count: an attempted connection to a
// down/unreachable host is not evidence that the finding endpoint was rechecked.
//
// A successful empty trace returns a non-nil empty slice (known zero coverage).
// Any read/format error returns nil so callers can retain the scan results while
// lifecycle closure fails closed.
func coveredHostsFromTrace(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open trace: %w", err)
	}
	defer f.Close()

	hosts := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxCoverageTraceLine)
	line := 0
	for sc.Scan() {
		line++
		var event nucleiTraceEvent
		if err := json.Unmarshal(sc.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode trace line %d: %w", line, err)
		}
		// The pinned Nuclei format always emits an error field. Count only its
		// explicit success sentinel; a missing/changed value is unknown and
		// therefore cannot become mitigation evidence.
		if event.Error == nil || *event.Error != "none" {
			continue
		}
		host := types.HostKey(event.Input)
		if host == "" {
			continue
		}
		hosts[host] = struct{}{}
		if len(hosts) > maxCoveredHosts {
			return nil, fmt.Errorf("trace exceeds %d distinct hosts", maxCoveredHosts)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read trace: %w", err)
	}

	out := make([]string, 0, len(hosts))
	for host := range hosts {
		out = append(out, host)
	}
	sort.Strings(out)
	return out, nil
}
