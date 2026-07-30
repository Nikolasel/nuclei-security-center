package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCoveredHostsFromTrace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	trace := "" +
		`{"type":"http","input":"https://Example.COM:443/a","address":"192.0.2.1:443","error":"none"}` + "\n" +
		`{"type":"http","input":"https://example.com/b","address":"192.0.2.1:443","error":"none"}` + "\n" +
		`{"type":"ssl","input":"[2001:db8::1]:443","error":"none"}` + "\n" +
		`{"type":"http","input":"https://unknown.invalid"}` + "\n" +
		`{"type":"http","input":"https://down.invalid","error":"i/o timeout"}` + "\n"
	if err := os.WriteFile(path, []byte(trace), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := coveredHostsFromTrace(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::1", "example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("covered hosts = %#v, want %#v", got, want)
	}
}

func TestCoveredHostsFromEmptyTraceIsKnownEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := coveredHostsFromTrace(path)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("covered hosts = %#v, want non-nil empty", got)
	}
}

func TestCoveredHostsFromMalformedTraceFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	if err := os.WriteFile(path, []byte("{bad json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := coveredHostsFromTrace(path)
	if err == nil || got != nil {
		t.Fatalf("covered hosts = %#v, err = %v; want nil/error", got, err)
	}
}
