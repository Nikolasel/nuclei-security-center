package backend

import (
	"slices"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func ptr[T any](v T) *T { return &v }

func TestValidateScanPolicy(t *testing.T) {
	// Missing name.
	if err := validateScanPolicy(&store.ScanPolicy{TemplateSetID: "ts1"}); err == nil {
		t.Error("expected error for missing name")
	}
	// A policy without an explicit template set is incomplete.
	if err := validateScanPolicy(&store.ScanPolicy{Name: "lean"}); err == nil {
		t.Error("policy accepted without template_set_id")
	}
	// A set-but-non-positive knob is rejected (buildArgs would silently drop it).
	for _, p := range []*store.ScanPolicy{
		{Name: "p", TemplateSetID: "ts1", RateLimit: ptr(0)},
		{Name: "p", TemplateSetID: "ts1", Concurrency: ptr(-5)},
		{Name: "p", TemplateSetID: "ts1", TimeoutSec: ptr(0)},
		{Name: "p", TemplateSetID: "ts1", MaxHostError: ptr(-1)},
		{Name: "p", TemplateSetID: "ts1", DiscoveryTimeoutSec: ptr(0)},
		{Name: "p", TemplateSetID: "ts1", DiscoveryPorts: "80,notaport"},
		{Name: "p", TemplateSetID: "ts1", DiscoveryPorts: "0"},
		{Name: "p", TemplateSetID: "ts1", DiscoveryPorts: "70000"},
		{Name: "p", TemplateSetID: "ts1", DiscoveryPorts: "9000-8000"}, // inverted range
		{Name: "p", TemplateSetID: "ts1", DiscoveryPorts: "80,,443"},   // empty entry
	} {
		if err := validateScanPolicy(p); err == nil {
			t.Errorf("invalid field accepted: %+v", p)
		}
	}
	// Valid discovery config (single ports + multiple ranges) is accepted + trimmed.
	dp := &store.ScanPolicy{Name: "disc", TemplateSetID: "ts1", DiscoveryPorts: " 80, 443, 8000-9000 ", DiscoveryTimeoutSec: ptr(120)}
	if err := validateScanPolicy(dp); err != nil {
		t.Errorf("valid discovery policy rejected: %v", err)
	}
	if dp.DiscoveryPorts != "80, 443, 8000-9000" {
		t.Errorf("discovery_ports not trimmed: %q", dp.DiscoveryPorts)
	}
	// Valid, trims name/template-set in place.
	ok := &store.ScanPolicy{Name: "  fragile  ", TemplateSetID: " ts1 ", RateLimit: ptr(20), MaxHostError: ptr(100)}
	if err := validateScanPolicy(ok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok.Name != "fragile" || ok.TemplateSetID != "ts1" {
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
	tg := &store.Target{
		Name: "  web  ",
		Hosts: []string{
			" Example.COM ", "example.com", "https://EXAMPLE.com/AdminPanel",
			"https://example.com/AdminPanel", "https://example.com/adminpanel",
		},
		Tags: []string{" prod ", ""},
	}
	if err := validateTarget(tg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tg.Name != "web" {
		t.Errorf("name not trimmed: %q", tg.Name)
	}
	if want := []string{
		"example.com", "https://example.com/AdminPanel", "https://example.com/adminpanel",
	}; !slices.Equal(tg.Hosts, want) {
		t.Errorf("hosts not trimmed and deduplicated: %v, want %v", tg.Hosts, want)
	}
	if len(tg.Tags) != 1 || tg.Tags[0] != "prod" {
		t.Errorf("tags not cleaned: %v", tg.Tags)
	}
}

func TestValidateTemplateSet(t *testing.T) {
	if err := validateTemplateSet(&store.TemplateSet{}); err == nil {
		t.Error("expected error for missing name")
	}
	ts := &store.TemplateSet{Name: " cves "}
	if err := validateTemplateSet(ts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts.Name != "cves" {
		t.Errorf("name not trimmed: %q", ts.Name)
	}
	if err := validateTemplateSet(&store.TemplateSet{
		Name: "exact", Mode: store.TemplateSetModeExact, ExcludedTemplateIDs: []string{"noisy"},
	}); err == nil || !strings.Contains(err.Error(), "only allowed for mode=exclude") {
		t.Fatalf("exact exclusions error = %v", err)
	}
	exclude := &store.TemplateSet{
		Name: " exclude ", Mode: store.TemplateSetModeExclude,
		ExcludedTemplateIDs: []string{" noisy ", "other"},
	}
	if err := validateTemplateSet(exclude); err != nil {
		t.Fatalf("exclude mode rejected: %v", err)
	}
	if exclude.Name != "exclude" || exclude.ExcludedTemplateIDs[0] != "noisy" {
		t.Fatalf("exclude mode was not normalized: %+v", exclude)
	}
}
