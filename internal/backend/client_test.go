package backend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestScannerClientDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/internal", http.StatusFound)
	}))
	defer origin.Close()

	client := NewScannerClient(origin.URL, "node-token")
	_, err := client.Results(context.Background(), "scan-1")
	if err == nil || !strings.Contains(err.Error(), "302 Found") {
		t.Fatalf("Results error = %v, want original 302 response", err)
	}
	if followed.Load() {
		t.Fatal("scanner client followed a redirect to a different origin")
	}
}

func TestScannerClientRejectsOversizedJSONResponses(t *testing.T) {
	response, err := json.Marshal(map[string]string{
		"padding": strings.Repeat("x", maxScannerJSONResponseBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write(response)
	}))
	defer server.Close()

	tests := []struct {
		name string
		call func(*ScannerClient) error
	}{
		{
			name: "start scan",
			call: func(client *ScannerClient) error {
				_, err := client.StartScan(context.Background(), types.ScanSpec{})
				return err
			},
		},
		{
			name: "status",
			call: func(client *ScannerClient) error {
				_, err := client.Status(context.Background(), "scan-1")
				return err
			},
		},
		{
			name: "capabilities",
			call: func(client *ScannerClient) error {
				_, err := client.Capabilities(context.Background())
				return err
			},
		},
		{
			name: "template validation",
			call: func(client *ScannerClient) error {
				_, err := client.ValidateTemplate(context.Background(), nil)
				return err
			},
		},
		{
			name: "template batch validation",
			call: func(client *ScannerClient) error {
				_, err := client.ValidateTemplateBatch(context.Background(), nil)
				return err
			},
		},
		{
			name: "template bundle",
			call: func(client *ScannerClient) error {
				_, err := client.PushBundle(context.Background(), nil)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := NewScannerClient(server.URL, "node-token")
			if err := test.call(client); err == nil {
				t.Fatal("client accepted an oversized scanner response")
			}
		})
	}
}

func TestScannerClientRejectsMultipleJSONValues(t *testing.T) {
	first, err := json.Marshal(types.StartScanResponse{ScanID: "scan-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(types.StartScanResponse{ScanID: "scan-2"})
	if err != nil {
		t.Fatal(err)
	}
	response := append(first, second...)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(response)
	}))
	defer server.Close()

	client := NewScannerClient(server.URL, "node-token")
	if _, err := client.StartScan(context.Background(), types.ScanSpec{}); err == nil {
		t.Fatal("client accepted multiple scanner JSON values")
	}
}

func TestScannerClientRejectsOversizedScanStatusCollections(t *testing.T) {
	discovered := make([]string, maxScannerStatusCollectionItems+1)
	for i := range discovered {
		discovered[i] = "host:443"
	}

	covered := make([]types.EndpointCoverage, maxScannerStatusCollectionItems+1)
	for i := range covered {
		covered[i] = types.EndpointCoverage{TemplateID: "template", Endpoint: "host:443"}
	}

	tests := []struct {
		name   string
		status types.ScanStatus
	}{
		{
			name:   "discovered targets",
			status: types.ScanStatus{DiscoveredTargets: discovered},
		},
		{
			name:   "covered endpoints",
			status: types.ScanStatus{CoveredEndpoints: covered},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := json.Marshal(test.status)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(response)
			}))
			defer server.Close()

			client := NewScannerClient(server.URL, "node-token")
			if _, err := client.Status(context.Background(), "scan-1"); err == nil {
				t.Fatal("client accepted an oversized scanner status collection")
			}
		})
	}
}

func TestScannerClientStatusDecodesAllFields(t *testing.T) {
	want := types.ScanStatus{
		ID:              "scan-1",
		State:           types.ScanRunning,
		NucleiVersion:   "3.4.0",
		TemplatesCommit: "commit-1",
		FindingCount:    3,
		Error:           "",
		Progress: &types.ScanProgress{
			Phase:    types.PhaseScanning,
			Percent:  42.5,
			Requests: 12,
			Total:    20,
			Hosts:    4,
			RPS:      2,
			Matched:  3,
		},
		DiscoveredTargets: []string{"host:443", "host:8443"},
		CoveredEndpoints: []types.EndpointCoverage{
			{TemplateID: "template-1", Endpoint: "host:443"},
		},
		CoverageWarning: "partial telemetry",
	}
	response, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(response)
	}))
	defer server.Close()

	client := NewScannerClient(server.URL, "node-token")
	got, err := client.Status(context.Background(), "scan-1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
}

func TestScannerClientStatusPreservesKnownEmptyCollections(t *testing.T) {
	response, err := json.Marshal(map[string]any{
		"discovered_targets": []string{},
		"covered_endpoints":  []types.EndpointCoverage{},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(response)
	}))
	defer server.Close()

	client := NewScannerClient(server.URL, "node-token")
	got, err := client.Status(context.Background(), "scan-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.DiscoveredTargets == nil || got.CoveredEndpoints == nil {
		t.Fatalf("status lost known empty collections: %+v", got)
	}
}

func TestScannerClientStatusIgnoresUnknownFields(t *testing.T) {
	response, err := json.Marshal(map[string]any{
		"state": types.ScanRunning,
		"future": map[string]any{
			"items": []any{1, map[string]any{"nested": true}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(response)
	}))
	defer server.Close()

	client := NewScannerClient(server.URL, "node-token")
	got, err := client.Status(context.Background(), "scan-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != types.ScanRunning {
		t.Fatalf("state = %q, want %q", got.State, types.ScanRunning)
	}
}

func TestScannerClientRejectsOversizedScanStatusValues(t *testing.T) {
	status := types.ScanStatus{
		DiscoveredTargets: []string{strings.Repeat("x", maxScannerNodeStringBytes+1)},
	}
	response, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(response)
	}))
	defer server.Close()

	client := NewScannerClient(server.URL, "node-token")
	if _, err := client.Status(context.Background(), "scan-1"); err == nil {
		t.Fatal("client accepted an oversized scanner status value")
	}
}

func TestScannerClientRejectsOversizedScanStatusStateAndProgress(t *testing.T) {
	tooLong := strings.Repeat("x", maxScannerNodeStringBytes+1)
	tests := []struct {
		name   string
		status types.ScanStatus
	}{
		{
			name:   "state",
			status: types.ScanStatus{State: types.ScanState(tooLong)},
		},
		{
			name: "progress phase",
			status: types.ScanStatus{
				Progress: &types.ScanProgress{Phase: types.ScanPhase(tooLong)},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := json.Marshal(test.status)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(response)
			}))
			defer server.Close()

			client := NewScannerClient(server.URL, "node-token")
			if _, err := client.Status(context.Background(), "scan-1"); err == nil {
				t.Fatal("client accepted an oversized scanner state or progress phase")
			}
		})
	}
}

func TestScannerClientValidateTemplate(t *testing.T) {
	const yaml = "id: custom-check\n"
	client := NewScannerClient("http://scanner.test", "node-token")
	client.httpForTimeout = func(timeout time.Duration) *http.Client {
		if timeout != 35*time.Second {
			t.Errorf("timeout = %s, want 35s", timeout)
		}
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/templates/validate" {
				t.Errorf("request = %s %s", r.Method, r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer node-token" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			if r.Header.Get("Content-Type") != "application/yaml" {
				t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != yaml {
				t.Errorf("body = %q", body)
			}
			response, _ := json.Marshal(types.TemplateValidationResult{
				Valid:         false,
				Errors:        []string{"invalid matcher"},
				NucleiVersion: "v3.11.0",
			})
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(string(response))),
				Request:    r,
			}, nil
		})}
	}

	result, err := client.ValidateTemplate(context.Background(), []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.NucleiVersion != "v3.11.0" || len(result.Errors) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestScannerClientValidateTemplateBatch(t *testing.T) {
	bundle := []byte("transient-bundle")
	client := NewScannerClient("http://scanner.test", "node-token")
	client.httpForTimeout = func(timeout time.Duration) *http.Client {
		if timeout != types.TemplateBatchValidationClientTimeout {
			t.Errorf("timeout = %s, want %s", timeout, types.TemplateBatchValidationClientTimeout)
		}
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/templates/validate-batch" {
				t.Errorf("request = %s %s", r.Method, r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer node-token" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			if r.Header.Get("Content-Type") != "application/gzip" {
				t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != string(bundle) {
				t.Errorf("body = %q", body)
			}
			response, _ := json.Marshal(types.TemplateBatchValidationResult{
				Valid: false,
				Failures: []types.TemplateValidationFailure{{
					TemplateID: "bad", Errors: []string{"invalid matcher"},
				}},
				Errors:        []string{},
				NucleiVersion: "v3.11.0",
			})
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(string(response))),
				Request:    r,
			}, nil
		})}
	}

	result, err := client.ValidateTemplateBatch(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.NucleiVersion != "v3.11.0" ||
		len(result.Failures) != 1 || result.Failures[0].TemplateID != "bad" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
