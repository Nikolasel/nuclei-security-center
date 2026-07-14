package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReadPasswordFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"plain", "s3cret", "s3cret"},
		{"trailing newline", "s3cret\n", "s3cret"},
		{"trailing crlf", "s3cret\r\n", "s3cret"},
		{"multiple trailing newlines", "s3cret\n\n", "s3cret"},
		{"interior space preserved", "s3 cret\n", "s3 cret"},
		{"leading space preserved", " s3cret\n", " s3cret"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pw")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := readPasswordFile(path)
			if err != nil {
				t.Fatalf("readPasswordFile: %v", err)
			}
			if got != c.want {
				t.Errorf("readPasswordFile(%q) = %q, want %q", c.content, got, c.want)
			}
		})
	}
}

func TestReadPasswordFileMissing(t *testing.T) {
	if _, err := readPasswordFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing password file, got nil")
	}
}

// OpenWithOptions should surface a DSN parse error before any network I/O, so a
// malformed DSN fails fast rather than hanging on connect retries.
func TestOpenWithOptionsBadDSN(t *testing.T) {
	if _, err := OpenWithOptions(context.Background(), "://not a dsn", Options{}); err == nil {
		t.Fatal("expected parse error for malformed DSN, got nil")
	}
}
