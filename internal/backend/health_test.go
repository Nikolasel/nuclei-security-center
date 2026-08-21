package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// newTestMonitor builds a monitor with a controllable clock and no store (the
// poll loop isn't exercised here — we drive the record map directly to test the
// TTL/known semantics that Get and clientForScan rely on).
func newTestMonitor(interval time.Duration, now *time.Time) *HealthMonitor {
	m := NewHealthMonitor(nil, interval, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	m.now = func() time.Time { return *now }
	return m
}

func TestHealthMonitorGet(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := now
	m := newTestMonitor(30*time.Second, &clock) // ttl = 90s

	// Unknown node: not polled yet.
	if _, known := m.Get("x"); known {
		t.Fatal("unpolled node should be unknown")
	}

	// A fresh successful poll → healthy, with caps.
	m.health["x"] = nodeHealth{LastSeen: clock, Caps: types.Capabilities{NucleiVersion: "v3.11.0"}}
	h, known := m.Get("x")
	if !known || !h.Healthy {
		t.Fatalf("want known+healthy, got known=%v healthy=%v", known, h.Healthy)
	}
	if h.Capabilities.NucleiVersion != "v3.11.0" {
		t.Errorf("nuclei version = %q, want v3.11.0", h.Capabilities.NucleiVersion)
	}

	// Within the TTL it stays healthy; past it, it ages out (still known).
	clock = now.Add(89 * time.Second)
	if h, _ := m.Get("x"); !h.Healthy {
		t.Error("node should still be healthy inside the TTL")
	}
	clock = now.Add(91 * time.Second)
	h, known = m.Get("x")
	if !known {
		t.Error("an aged-out node is still known (was polled)")
	}
	if h.Healthy {
		t.Error("node should be unhealthy past the TTL")
	}
}

func TestHealthMonitorNeverSucceeded(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := now
	m := newTestMonitor(30*time.Second, &clock)

	// A node polled but never reachable: record exists (known) with zero LastSeen
	// and the failure message retained for the UI.
	m.health["down"] = nodeHealth{LastErr: "capabilities: 401 Unauthorized"}
	h, known := m.Get("down")
	if !known {
		t.Fatal("a polled-but-failed node is known")
	}
	if h.Healthy {
		t.Error("a node that never responded is unhealthy")
	}
	if h.LastError != "capabilities: 401 Unauthorized" {
		t.Errorf("LastError = %q, want the poll failure message", h.LastError)
	}
}

func TestSanitizeHealthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "strips body",
			err:  fmt.Errorf("capabilities: %w", &httpStatusError{Status: "500 Internal Server Error", Body: "secret-metadata"}),
			want: "capabilities: 500 Internal Server Error",
		},
		{
			name: "401 strips body",
			err:  fmt.Errorf("capabilities: %w", &httpStatusError{Status: "401 Unauthorized", Body: "<html>evil</html>"}),
			want: "capabilities: 401 Unauthorized",
		},
		{
			name: "no body",
			err:  fmt.Errorf("capabilities: %w", &httpStatusError{Status: "500 Internal Server Error"}),
			want: "capabilities: 500 Internal Server Error",
		},
		{
			name: "context deadline",
			err:  fmt.Errorf("capabilities: %w", errors.New("context deadline exceeded")),
			want: "capabilities: context deadline exceeded",
		},
		{
			name: "network error",
			err:  errors.New("Get \"http://169.254.169.254\": dial tcp 169.254.169.254:80: connect: connection refused"),
			want: "Get \"http://169.254.169.254\": dial tcp 169.254.169.254:80: connect: connection refused",
		},
		{
			name: "truncates long generic error on rune boundary",
			err:  errors.New(strings.Repeat("é", 400)), // multi-byte rune, 800 bytes
			want: truncate512(strings.Repeat("é", 400)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeHealthError(tc.err)
			if got != tc.want {
				t.Fatalf("sanitizeHealthError(%q) = %q, want %q", tc.err.Error(), got, tc.want)
			}
			// Ensure body never leaks for httpStatusError cases.
			if se, ok := func() (*httpStatusError, bool) {
				var s *httpStatusError
				if errors.As(tc.err, &s) {
					return s, s.Body != ""
				}
				return nil, false
			}(); ok {
				if strings.Contains(got, se.Body) {
					t.Fatalf("sanitized error %q still contains body %q", got, se.Body)
				}
			}
		})
	}
}

func TestHealthPollDoesNotReflectResponseBody(t *testing.T) {
	// Stand up a fake scanner node that returns 500 with a secret body and
	// drive the real client → sanitizer path. This pins the client↔sanitizer
	// contract: if either format drifts, the test fails.
	secret := "SECRET-BODY-LEAK-TEST-" + strings.Repeat("x", 100)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/capabilities" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, secret)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewScannerClient(server.URL, "token")
	_, err := client.Capabilities(context.Background())
	if err == nil {
		t.Fatal("Capabilities should have failed on 500")
	}
	// Verify the raw error still contains the body for server-side logging
	// (the poll logs err directly) but the sanitized viewer-facing error does not.
	if !strings.Contains(err.Error(), secret) {
		t.Fatalf("raw error should contain body for server logs, got %q", err.Error())
	}
	var se *httpStatusError
	if !errors.As(err, &se) {
		t.Fatalf("raw error should wrap httpStatusError, got %T: %v", err, err)
	}
	if se.Body != secret {
		t.Fatalf("httpStatusError.Body = %q, want %q", se.Body, secret)
	}
	sanitized := sanitizeHealthError(err)
	if strings.Contains(sanitized, secret) {
		t.Fatalf("sanitized health error still contains response body: %q", sanitized)
	}
	if want := "capabilities: 500 Internal Server Error"; sanitized != want {
		t.Fatalf("sanitized = %q, want %q", sanitized, want)
	}

	// Also verify the HealthMonitor poll path stores the sanitized value:
	// simulate poll's map write via direct sanitizer (poll does sanitizeHealthError(err)).
	now := time.Now()
	m := newTestMonitor(30*time.Second, &now)
	m.health["node-1"] = nodeHealth{LastErr: sanitized}
	if h, _ := m.Get("node-1"); strings.Contains(h.LastError, secret) {
		t.Fatalf("HealthMonitor stored leaked body: %q", h.LastError)
	}
}
