package backend

import (
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func ptr[T any](v T) *T { return &v }

func TestValidateScanPolicy(t *testing.T) {
	// Missing name / missing target (a policy must name a target — the scope).
	if err := validateScanPolicy(&store.ScanPolicy{TargetID: "t1"}); err == nil {
		t.Error("expected error for missing name")
	}
	if err := validateScanPolicy(&store.ScanPolicy{Name: "p"}); err == nil {
		t.Error("expected error for missing target_id")
	}
	// A target + all knobs nil (every knob "use the default", no template set) is
	// valid — the leanest complete policy.
	if err := validateScanPolicy(&store.ScanPolicy{Name: "lean", TargetID: "t1"}); err != nil {
		t.Errorf("target-only policy rejected: %v", err)
	}
	// A set-but-non-positive knob is rejected (buildArgs would silently drop it).
	for _, p := range []*store.ScanPolicy{
		{Name: "p", TargetID: "t1", RateLimit: ptr(0)},
		{Name: "p", TargetID: "t1", Concurrency: ptr(-5)},
		{Name: "p", TargetID: "t1", TimeoutSec: ptr(0)},
		{Name: "p", TargetID: "t1", MaxHostError: ptr(-1)},
	} {
		if err := validateScanPolicy(p); err == nil {
			t.Errorf("non-positive knob accepted: %+v", p)
		}
	}
	// Valid, trims name/target/template-set in place.
	ok := &store.ScanPolicy{Name: "  fragile  ", TargetID: " t1 ", TemplateSetID: " ts1 ", RateLimit: ptr(20), MaxHostError: ptr(100)}
	if err := validateScanPolicy(ok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok.Name != "fragile" || ok.TargetID != "t1" || ok.TemplateSetID != "ts1" {
		t.Errorf("fields not trimmed: %+v", ok)
	}
}

func TestValidateHost(t *testing.T) {
	valid := []string{
		"scanme.sh",
		"example.com",
		"localhost",
		"sub.domain.example.com",
		"10.0.0.1",
		"10.0.0.0/24",
		"192.168.1.0/28",
		"https://example.com",
		"https://example.com/path?q=1",
		"http://10.0.0.1:8080/x",
		"example.com:8443",
		"1.2.3.4:443",
		"::1",
	}
	for _, h := range valid {
		if err := validateHost(h); err != nil {
			t.Errorf("validateHost(%q) = %v, want nil", h, err)
		}
	}

	invalid := []string{
		"",
		"has space",
		"bad_underscore.com",
		"10.0.0.0/999",
		"http://",
		"example.com:70000", // port out of range
		"-leadinghyphen.com",
	}
	for _, h := range invalid {
		if err := validateHost(h); err == nil {
			t.Errorf("validateHost(%q) = nil, want error", h)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	// Missing name.
	if err := validateTarget(&store.Target{Hosts: []string{"example.com"}}); err == nil {
		t.Error("expected error for missing name")
	}
	// No hosts.
	if err := validateTarget(&store.Target{Name: "web"}); err == nil {
		t.Error("expected error for missing hosts")
	}
	// One bad host fails the whole target.
	if err := validateTarget(&store.Target{Name: "web", Hosts: []string{"ok.com", "bad host"}}); err == nil {
		t.Error("expected error for invalid host in list")
	}
	// Valid, and it trims/normalizes in place.
	tg := &store.Target{Name: "  web  ", Hosts: []string{" example.com "}, Tags: []string{" prod ", ""}}
	if err := validateTarget(tg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tg.Name != "web" {
		t.Errorf("name not trimmed: %q", tg.Name)
	}
	if len(tg.Hosts) != 1 || tg.Hosts[0] != "example.com" {
		t.Errorf("host not trimmed: %v", tg.Hosts)
	}
	if len(tg.Tags) != 1 || tg.Tags[0] != "prod" {
		t.Errorf("tags not cleaned: %v", tg.Tags)
	}
}

func TestValidateTemplateSet(t *testing.T) {
	if err := validateTemplateSet(&store.TemplateSet{}); err == nil {
		t.Error("expected error for missing name")
	}
	ts := &store.TemplateSet{Name: " cves ", Severities: []string{" critical ", ""}, GitRef: " main "}
	if err := validateTemplateSet(ts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts.Name != "cves" || ts.GitRef != "main" {
		t.Errorf("not trimmed: name=%q gitref=%q", ts.Name, ts.GitRef)
	}
	if len(ts.Severities) != 1 || ts.Severities[0] != "critical" {
		t.Errorf("severities not cleaned: %v", ts.Severities)
	}
}

func TestValidateTemplateSetRejectsBadPathsAndRefs(t *testing.T) {
	badPaths := []string{"/etc", "../../x", "a/../b", "-templates", "~/x", "has space"}
	for _, p := range badPaths {
		if err := validateTemplateSet(&store.TemplateSet{Name: "s", Paths: []string{p}}); err == nil {
			t.Errorf("path %q accepted, want rejected", p)
		}
	}
	badRefs := []string{"a b", "..", "main..evil", "-x", "$(id)", "a;b"}
	for _, r := range badRefs {
		if err := validateTemplateSet(&store.TemplateSet{Name: "s", GitRef: r}); err == nil {
			t.Errorf("gitref %q accepted, want rejected", r)
		}
	}
	// Legit relative paths and refs pass.
	ok := &store.TemplateSet{Name: "s", Paths: []string{"http/cves", "misconfiguration/x.yaml"}, GitRef: "v9.6.3"}
	if err := validateTemplateSet(ok); err != nil {
		t.Errorf("valid template set rejected: %v", err)
	}
}
