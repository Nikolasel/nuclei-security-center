package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestCoveredEndpointsFromRealTraceShape(t *testing.T) {
	trace, err := os.Open(filepath.Join("testdata", "nuclei-v3.11-trace.jsonl"))
	if err != nil {
		t.Fatalf("open pinned Nuclei trace fixture: %v", err)
	}
	defer trace.Close()
	got := coveredEndpointsFromTrace(trace, map[string]string{
		"/Users/neller/nuclei-templates/http/technologies/opencart-detect.yaml": "opencart-detect",
	})
	want := []types.EndpointCoverage{
		{TemplateID: "opencart-detect", Endpoint: "127.0.0.1:18091"},
	}
	if len(got.Endpoints) != len(want) || got.Endpoints[0] != want[0] {
		t.Fatalf("covered endpoints = %#v, want %#v", got.Endpoints, want)
	}
	if got.Warning != "" {
		t.Fatalf("warning = %q, want none", got.Warning)
	}
}

func TestCoveredEndpointsSameHostDifferentPortAndTemplate(t *testing.T) {
	trace := "" +
		`{"template":"/bundle/a.yaml","type":"http","input":"http://h.invalid:8080","address":"h.invalid:8080","error":"none"}` + "\n" +
		`{"template":"/bundle/b.yaml","type":"http","input":"http://h.invalid:9999","address":"h.invalid:9999","error":"port closed or filtered"}` + "\n"
	got := coveredEndpointsFromTrace(strings.NewReader(trace), map[string]string{
		"/bundle/a.yaml": "template-a",
		"/bundle/b.yaml": "template-b",
	})
	want := []types.EndpointCoverage{{TemplateID: "template-a", Endpoint: "h.invalid:8080"}}
	if len(got.Endpoints) != 1 || got.Endpoints[0] != want[0] {
		t.Fatalf("covered endpoints = %#v, want %#v", got.Endpoints, want)
	}
}

func TestCoveredEndpointsMalformedTailKeepsValidEvidence(t *testing.T) {
	trace := `{"template":"/bundle/a.yaml","type":"http","address":"h.invalid:443","error":"none"}` +
		"\n" + `{"truncated":`
	got := coveredEndpointsFromTrace(strings.NewReader(trace), map[string]string{"/bundle/a.yaml": "a"})
	if len(got.Endpoints) != 1 || got.Endpoints[0].Endpoint != "h.invalid:443" {
		t.Fatalf("covered endpoints = %#v, want retained valid evidence", got.Endpoints)
	}
	if !strings.Contains(got.Warning, "skipped 1 malformed") {
		t.Fatalf("warning = %q", got.Warning)
	}
}

func TestCoveredEndpointsEmptyTraceIsKnownEmpty(t *testing.T) {
	got := coveredEndpointsFromTrace(strings.NewReader(""), nil)
	if got.Endpoints == nil || len(got.Endpoints) != 0 || got.Warning != "" {
		t.Fatalf("result = %#v, want known empty", got)
	}
}

func TestCoveredEndpointsWhollyMalformedTraceFailsClosed(t *testing.T) {
	got := coveredEndpointsFromTrace(strings.NewReader("{bad json}\n"), nil)
	if got.Endpoints != nil || !strings.Contains(got.Warning, "no decodable records") {
		t.Fatalf("result = %#v, want nil coverage warning", got)
	}
}

func TestCoveredEndpointsChangedTraceShapeFailsClosed(t *testing.T) {
	got := coveredEndpointsFromTrace(strings.NewReader(
		`{"template":"/bundle/a.yaml","type":"http","address":"h.invalid:443"}`+"\n",
	), map[string]string{"/bundle/a.yaml": "a"})
	if got.Endpoints != nil || !strings.Contains(got.Warning, "no explicit request status") {
		t.Fatalf("result = %#v, want changed-format warning", got)
	}
}

func TestCoveredEndpointsFromTraceFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create trace FIFO: %v", err)
	}
	reader, anchor, err := openCoverageTraceFIFO(path)
	if err != nil {
		t.Fatalf("open trace FIFO reader before writer: %v", err)
	}
	defer reader.Close()
	defer anchor.Close()
	resultCh := make(chan coverageResult, 1)
	go func() {
		resultCh <- coveredEndpointsFromTrace(reader, map[string]string{
			"/bundle/a.yaml": "template-a",
		})
	}()
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open trace FIFO writer: %v", err)
	}
	if _, err := writer.WriteString(
		`{"template":"/bundle/a.yaml","type":"http","address":"h.invalid:8080","error":"none"}` + "\n",
	); err != nil {
		t.Fatalf("write trace FIFO: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close trace FIFO: %v", err)
	}
	if err := anchor.Close(); err != nil {
		t.Fatalf("close trace FIFO anchor: %v", err)
	}
	got := <-resultCh
	want := types.EndpointCoverage{TemplateID: "template-a", Endpoint: "h.invalid:8080"}
	if len(got.Endpoints) != 1 || got.Endpoints[0] != want || got.Warning != "" {
		t.Fatalf("FIFO coverage = %#v, want %#v", got, want)
	}
}

func TestCoverageFIFOWithoutNucleiWriterCompletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create trace FIFO: %v", err)
	}
	reader, anchor, err := openCoverageTraceFIFO(path)
	if err != nil {
		t.Fatalf("prepare trace FIFO: %v", err)
	}
	defer reader.Close()
	resultCh := make(chan coverageResult, 1)
	go func() {
		resultCh <- coveredEndpointsFromTrace(reader, nil)
	}()
	if err := anchor.Close(); err != nil {
		t.Fatalf("close trace FIFO anchor: %v", err)
	}
	select {
	case got := <-resultCh:
		if got.Endpoints == nil || len(got.Endpoints) != 0 || got.Warning != "" {
			t.Fatalf("no-writer coverage = %#v, want known empty", got)
		}
	case <-time.After(time.Second):
		t.Fatal("trace reducer remained blocked without a Nuclei writer")
	}
}

func TestFindingsWithoutCoverageFailClosed(t *testing.T) {
	got := validateCoverageAgainstFindings(coverageResult{
		Endpoints: []types.EndpointCoverage{},
	}, 2)
	if got.Endpoints != nil || !strings.Contains(got.Warning, "produced 2 findings") {
		t.Fatalf("validated coverage = %#v, want fail-closed contradiction warning", got)
	}
}
