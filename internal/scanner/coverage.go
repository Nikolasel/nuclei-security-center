package scanner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

const (
	maxCoverageTraceLine = 1024 * 1024
	maxCoveragePairs     = 250_000
)

type nucleiTraceEvent struct {
	Template string  `json:"template"`
	Type     string  `json:"type"`
	Input    string  `json:"input"`
	Address  string  `json:"address"`
	Error    *string `json:"error"`
}

type coverageResult struct {
	Endpoints []types.EndpointCoverage
	Warning   string
}

// coveredEndpointsFromTrace extracts template+endpoint positive evidence from
// Nuclei's -trace-log JSONL. Only explicit error:"none" records count. The
// template path is resolved back to the manifest id that Runner passed to
// Nuclei, and address supplies the actual host:port that answered.
//
// Malformed/oversized individual records are skipped while the stream continues
// to be drained, so a truncated final line cannot deadlock the FIFO or discard
// otherwise valid evidence. A wholly unreadable non-empty trace returns nil
// coverage (unknown/fail closed); a genuinely empty trace returns non-nil empty.
func coveredEndpointsFromTrace(r io.Reader, templateIDByPath map[string]string) coverageResult {
	seen := map[types.EndpointCoverage]struct{}{}
	reader := bufio.NewReaderSize(r, 64*1024)
	var (
		line              []byte
		oversized         bool
		nonEmptyRecords   int
		decodedRecords    int
		statusRecords     int
		malformedRecords  int
		unmappedSuccesses int
		overflow          bool
		readErr           error
	)

	process := func(raw []byte, tooLarge bool) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 && !tooLarge {
			return
		}
		nonEmptyRecords++
		if tooLarge {
			malformedRecords++
			return
		}
		var event nucleiTraceEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			malformedRecords++
			return
		}
		decodedRecords++
		if event.Error == nil {
			return
		}
		statusRecords++
		if *event.Error != "none" {
			return
		}
		templateID, ok := templateIDByPath[filepath.Clean(event.Template)]
		if !ok {
			unmappedSuccesses++
			return
		}
		endpoint := types.EndpointKey(event.Address, event.Type)
		if endpoint == "" {
			endpoint = types.EndpointKey(event.Input, event.Type)
		}
		if endpoint == "" {
			unmappedSuccesses++
			return
		}
		pair := types.EndpointCoverage{TemplateID: templateID, Endpoint: endpoint}
		if _, exists := seen[pair]; exists || overflow {
			return
		}
		seen[pair] = struct{}{}
		if len(seen) > maxCoveragePairs {
			overflow = true
			seen = nil
		}
	}

	for {
		fragment, err := reader.ReadSlice('\n')
		switch err {
		case nil:
			if !oversized {
				if len(line)+len(fragment) <= maxCoverageTraceLine {
					line = append(line, fragment...)
				} else {
					oversized = true
				}
			}
			process(line, oversized)
			line = line[:0]
			oversized = false
		case bufio.ErrBufferFull:
			if !oversized {
				if len(line)+len(fragment) <= maxCoverageTraceLine {
					line = append(line, fragment...)
				} else {
					oversized = true
					line = line[:0]
				}
			}
		case io.EOF:
			if len(fragment) > 0 || len(line) > 0 || oversized {
				if !oversized {
					if len(line)+len(fragment) <= maxCoverageTraceLine {
						line = append(line, fragment...)
					} else {
						oversized = true
					}
				}
				process(line, oversized)
			}
			goto done
		default:
			readErr = err
			goto done
		}
	}

done:
	var warnings []string
	if readErr != nil {
		return coverageResult{Warning: fmt.Sprintf("endpoint coverage unavailable: read Nuclei trace: %v", readErr)}
	}
	if overflow {
		return coverageResult{Warning: fmt.Sprintf(
			"endpoint coverage unavailable: exceeded %d distinct template/endpoint pairs",
			maxCoveragePairs,
		)}
	}
	if nonEmptyRecords > 0 && decodedRecords == 0 {
		return coverageResult{Warning: "endpoint coverage unavailable: Nuclei trace contained no decodable records"}
	}
	if decodedRecords > 0 && statusRecords == 0 {
		return coverageResult{Warning: "endpoint coverage unavailable: Nuclei trace contained no explicit request status"}
	}
	if malformedRecords > 0 {
		warnings = append(warnings, fmt.Sprintf("skipped %d malformed Nuclei trace records", malformedRecords))
	}
	if unmappedSuccesses > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"skipped %d successful trace records without a known template/endpoint",
			unmappedSuccesses,
		))
	}

	out := make([]types.EndpointCoverage, 0, len(seen))
	for pair := range seen {
		out = append(out, pair)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TemplateID != out[j].TemplateID {
			return out[i].TemplateID < out[j].TemplateID
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return coverageResult{Endpoints: out, Warning: strings.Join(warnings, "; ")}
}

// openCoverageTraceFIFO installs the reader before Nuclei can attempt to open
// the writer. The read/write anchor avoids both sides of the FIFO handshake
// blocking; Runner closes it after Nuclei exits so the reader receives EOF even
// when Nuclei failed before opening its own writer.
func openCoverageTraceFIFO(path string) (reader, anchor *os.File, err error) {
	anchor, err = os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open trace pipe anchor: %w", err)
	}
	reader, err = os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		_ = anchor.Close()
		return nil, nil, fmt.Errorf("open trace pipe reader: %w", err)
	}
	return reader, anchor, nil
}
