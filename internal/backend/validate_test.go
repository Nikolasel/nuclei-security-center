package backend

import (
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

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
