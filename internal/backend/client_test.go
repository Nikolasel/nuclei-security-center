package backend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

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
		if timeout != 130*time.Second {
			t.Errorf("timeout = %s, want 130s", timeout)
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
