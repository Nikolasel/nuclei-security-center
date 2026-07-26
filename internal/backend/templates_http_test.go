package backend

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

const validCustomYAML = `id: my-custom-check
info:
  name: My Custom Check
  author: sec-team
  severity: high
  tags: internal,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}/health"
    matchers:
      - type: status
        status:
          - 200
`

func TestParseCustomTemplate(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	tmpl, ok := s.parseCustomTemplate(rr, []byte(validCustomYAML))
	if !ok {
		t.Fatalf("parseCustomTemplate failed: %d %s", rr.Code, rr.Body)
	}
	if tmpl.ID != "my-custom-check" {
		t.Errorf("id = %q, want my-custom-check", tmpl.ID)
	}
	if tmpl.Path != "custom/my-custom-check.yaml" {
		t.Errorf("path = %q, want custom/my-custom-check.yaml", tmpl.Path)
	}
	if tmpl.Severity != "high" || tmpl.Name != "My Custom Check" {
		t.Errorf("unexpected metadata: %+v", tmpl)
	}
	if tmpl.YAML != validCustomYAML {
		t.Errorf("yaml not preserved byte-for-byte")
	}
}

func TestParseCustomTemplateRejects(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"no id", "info:\n  name: X\n  severity: low\n"},
		{"id with slash", "id: http/cves/x\ninfo:\n  name: X\n  severity: low\n"},
		{"missing info name", "id: ok\ninfo:\n  severity: low\n"},
		{"not yaml", "::: not : valid : yaml :::"},
		{"no executable section", "id: inert\ninfo:\n  name: X\n  severity: low\n"},
		{"bad severity", "id: typo\ninfo:\n  name: X\n  severity: hihg\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{}
			rr := httptest.NewRecorder()
			if _, ok := s.parseCustomTemplate(rr, []byte(c.yaml)); ok {
				t.Fatalf("expected rejection for %q", c.name)
			}
			if rr.Code != 400 {
				t.Errorf("status = %d, want 400", rr.Code)
			}
		})
	}
}

// The id inside the YAML is the primary key; editing must not swap it. The
// handler rejects a mismatch before touching the store (so a nil store is fine).
func TestHandleUpdateTemplateRejectsIDMismatch(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/templates/different-id", strings.NewReader(validCustomYAML))
	req.SetPathValue("id", "different-id")
	s.handleUpdateTemplate(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400 (body: %s)", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "does not match") {
		t.Errorf("unexpected body: %s", rr.Body)
	}
}

// An unknown source value is rejected as a 400 before the store is queried.
func TestHandleListTemplatesRejectsBadSource(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/templates?source=bogus", nil)
	s.handleListTemplates(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleListTemplatesRejectsBadSort(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/templates?sort=updated", nil)
	s.handleListTemplates(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestReadTemplateBodyRejectsEmpty(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/templates", strings.NewReader(""))
	if _, ok := readTemplateBody(rr, req); ok {
		t.Fatal("expected empty-body rejection")
	}
	if rr.Code != 400 {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestAuthorizeCustomTemplateMapsVerdicts(t *testing.T) {
	t.Run("invalid is bad request", func(t *testing.T) {
		s := &Server{templateValidator: func(context.Context, []byte) (types.TemplateValidationResult, error) {
			return types.TemplateValidationResult{
				Valid:         false,
				Errors:        []string{"invalid matcher"},
				NucleiVersion: "v3.11.0",
			}, nil
		}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/templates", nil)
		if _, ok := s.authorizeCustomTemplate(rr, req, []byte(validCustomYAML)); ok {
			t.Fatal("expected invalid verdict rejection")
		}
		if rr.Code != 400 || !strings.Contains(rr.Body.String(), "invalid matcher") {
			t.Fatalf("response = %d %q", rr.Code, rr.Body.String())
		}
	})

	t.Run("node failure is unavailable", func(t *testing.T) {
		s := &Server{templateValidator: func(context.Context, []byte) (types.TemplateValidationResult, error) {
			return types.TemplateValidationResult{}, errors.New("node unavailable")
		}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/templates", nil)
		if _, ok := s.authorizeCustomTemplate(rr, req, []byte(validCustomYAML)); ok {
			t.Fatal("expected unavailable rejection")
		}
		if rr.Code != 503 || rr.Header().Get("Retry-After") != "5" {
			t.Fatalf("response = %d Retry-After=%q", rr.Code, rr.Header().Get("Retry-After"))
		}
	})

	t.Run("valid reports engine", func(t *testing.T) {
		s := &Server{templateValidator: func(context.Context, []byte) (types.TemplateValidationResult, error) {
			return types.TemplateValidationResult{Valid: true, Errors: []string{}, NucleiVersion: "v3.11.0"}, nil
		}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/templates", nil)
		result, ok := s.authorizeCustomTemplate(rr, req, []byte(validCustomYAML))
		if !ok || result.NucleiVersion != "v3.11.0" {
			t.Fatalf("result = %+v, ok = %v", result, ok)
		}
	})
}
