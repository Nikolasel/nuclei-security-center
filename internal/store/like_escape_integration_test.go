package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestLikeEscapingPostgresLiteralMatching verifies that escaped LIKE patterns
// match literally in PostgreSQL: a filter value containing %/_/\ matches a row
// that contains that character but not a row that would have matched via wildcard
// semantics, while outer wildcards still provide substring matching.
func TestLikeEscapingPostgresLiteralMatching(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	// --- Raw pattern semantics: escaped %/_/\ are literal with ESCAPE '\' ---
	t.Run("raw ILIKE ESCAPE literal", func(t *testing.T) {
		cases := []struct {
			name    string
			value   string
			pattern string
			want    bool
		}{
			{name: "percent literal matches", value: "a%b", pattern: "%a\\%b%", want: true},
			{name: "percent literal non-match", value: "aXb", pattern: "%a\\%b%", want: false},
			{name: "underscore literal matches", value: "a_b", pattern: "%a\\_b%", want: true},
			{name: "underscore literal non-match", value: "aXb", pattern: "%a\\_b%", want: false},
			{name: "backslash literal matches", value: "a\\b", pattern: "%a\\\\b%", want: true},
			{name: "trailing backslash matches", value: "abc\\", pattern: "%abc\\\\%", want: true},
			{name: "trailing backslash non-match", value: "abc", pattern: "%abc\\\\%", want: false},
			{name: "substring still works", value: "xxa%bxx", pattern: "%a\\%b%", want: true},
			{name: "plain substring still works", value: "xxhellowxx", pattern: "%hello%", want: true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var matched bool
				// Use explicit ESCAPE as occurrence/template paths do.
				if err := st.pool.QueryRow(ctx, `SELECT $1 ILIKE $2 ESCAPE '\'`, tc.value, tc.pattern).Scan(&matched); err != nil {
					t.Fatalf("query: %v", err)
				}
				if matched != tc.want {
					t.Fatalf("value %q ILIKE %q = %v, want %v", tc.value, tc.pattern, matched, tc.want)
				}
			})
		}
	})

	// ILIKE ANY (findingquery) relies on default backslash escape, no explicit ESCAPE clause.
	t.Run("raw ILIKE ANY default escape", func(t *testing.T) {
		var matched bool
		if err := st.pool.QueryRow(ctx, `SELECT $1 ILIKE ANY($2)`, "a%b", []string{"%a\\%b%"}).Scan(&matched); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !matched {
			t.Fatalf("ILIKE ANY should match literal %% with default escape")
		}
		if err := st.pool.QueryRow(ctx, `SELECT $1 ILIKE ANY($2)`, "aXb", []string{"%a\\%b%"}).Scan(&matched); err != nil {
			t.Fatalf("query: %v", err)
		}
		if matched {
			t.Fatalf("ILIKE ANY should not match aXb with escaped %% pattern")
		}
		if err := st.pool.QueryRow(ctx, `SELECT $1 ILIKE ANY($2)`, "a_b", []string{"%a\\_b%"}).Scan(&matched); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !matched {
			t.Fatalf("ILIKE ANY should match literal _")
		}
		if err := st.pool.QueryRow(ctx, `SELECT $1 ILIKE ANY($2)`, "abc\\", []string{"%abc\\\\%"}).Scan(&matched); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !matched {
			t.Fatalf("ILIKE ANY should match trailing backslash")
		}
	})

	// --- Template catalog filter via ListTemplates ---
	t.Run("templates ILIKE ESCAPE via ListTemplates", func(t *testing.T) {
		// Insert two active templates: one with a literal % in id/name, one without.
		_, err := st.pool.Exec(ctx, `INSERT INTO templates (id, source, path, yaml, content_sha256, name, severity, description, tags, availability)
		 VALUES
		 ('like-test-%-id', 'custom', 'path/like-test-%', 'yaml:%', 'sha1', 'has percent %', 'info', 'desc', '{}', 'active'),
		 ('like-test-normal-id', 'custom', 'path/like-test-normal', 'yaml:normal', 'sha2', 'normal', 'info', 'desc', '{}', 'active')`)
		if err != nil {
			t.Fatalf("insert templates: %v", err)
		}
		// Query containing literal % should match only the % template, not the normal one.
		templates, total, err := st.ListTemplates(ctx, TemplateFilter{Query: "like-test-%"}, 50, 0)
		if err != nil {
			t.Fatalf("list templates with percent: %v", err)
		}
		if total != 1 || len(templates) != 1 || templates[0].ID != "like-test-%-id" {
			t.Fatalf("percent query total=%d templates=%v, want 1 with id like-test-%%-id", total, templates)
		}
		// Underscore literal
		_, err = st.pool.Exec(ctx, `INSERT INTO templates (id, source, path, yaml, content_sha256, name, severity, description, tags, availability)
		 VALUES ('like-test-_-id', 'custom', 'path/like-test-_', 'yaml:_', 'sha3', 'has_underscore', 'info', 'desc', '{}', 'active')`)
		if err != nil {
			t.Fatalf("insert underscore template: %v", err)
		}
		templates, total, err = st.ListTemplates(ctx, TemplateFilter{Query: "like-test-_"}, 50, 0)
		if err != nil {
			t.Fatalf("list templates with underscore: %v", err)
		}
		found := false
		for _, tmpl := range templates {
			if tmpl.ID == "like-test-_-id" {
				found = true
			}
			if tmpl.ID == "like-test-%-id" {
				t.Fatalf("underscore query incorrectly matched percent template")
			}
		}
		if !found {
			t.Fatalf("underscore query did not match expected template, got %v", templates)
		}
		// Substring wrapping: query "percent" should match "has percent %" via surrounding %.
		templates, total, err = st.ListTemplates(ctx, TemplateFilter{Query: "percent"}, 50, 0)
		if err != nil {
			t.Fatalf("list templates substring: %v", err)
		}
		found = false
		for _, tmpl := range templates {
			if tmpl.ID == "like-test-%-id" {
				found = true
			}
		}
		if !found {
			t.Fatalf("substring query 'percent' should match template with percent in name, got %v", templates)
		}
		// Trailing backslash literal
		_, err = st.pool.Exec(ctx, `INSERT INTO templates (id, source, path, yaml, content_sha256, name, severity, description, tags, availability)
		 VALUES ('like-test-backslash-id', 'custom', 'path/like-test-backslash', 'yaml:bs', 'sha4', 'has trailing \', 'info', 'desc', '{}', 'active')`)
		if err != nil {
			t.Fatalf("insert backslash template: %v", err)
		}
		templates, total, err = st.ListTemplates(ctx, TemplateFilter{Query: "trailing \\"}, 50, 0)
		if err != nil {
			t.Fatalf("list templates with backslash: %v", err)
		}
		found = false
		for _, tmpl := range templates {
			if tmpl.ID == "like-test-backslash-id" {
				found = true
			}
		}
		if !found {
			t.Fatalf("backslash query did not match expected template, got %v", templates)
		}
	})

	// --- Occurrence filter via ListFindings (legacy occurrence view) ---
	t.Run("occurrences ILIKE ESCAPE via ListFindings", func(t *testing.T) {
		target, err := st.CreateTarget(ctx, Target{Name: "like-occ-target-" + types.NewID(), Hosts: []string{"like.test.invalid"}})
		if err != nil {
			t.Fatalf("create target: %v", err)
		}
		spec := types.ScanSpec{Targets: target.Hosts, Templates: types.TemplateSelector{TemplateIDs: []string{"tpl"}, TemplatesCommit: "test"}}
		scanID, err := st.CreateScan(ctx, spec, ScanLink{TargetID: target.ID})
		if err != nil {
			t.Fatalf("create scan: %v", err)
		}
		// Ingest two occurrences: one with host containing %, one normal.
		ingest := func(host string, template string) {
			f := types.NucleiFinding{TemplateID: template, Host: host, MatchedAt: "https://like.test.invalid", Type: "http", Info: types.NucleiInfo{Name: template, Severity: "info"}}
			raw, _ := json.Marshal(f)
			if err := st.IngestFinding(ctx, scanID, target.ID, f, raw); err != nil {
				t.Fatalf("ingest host %q: %v", host, err)
			}
		}
		ingest("host%withpercent", "tpl-a")
		ingest("hostnormal", "tpl-b")
		ingest("host_with_underscore", "tpl-c")
		ingest("host\\with\\backslash", "tpl-d")
		ingest("hosttrailing\\", "tpl-e")

		// Host filter containing % should match only host%withpercent.
		rows, total, err := st.ListFindings(ctx, FindingFilter{ScanID: scanID, Host: "host%with"})
		if err != nil {
			t.Fatalf("list findings host %%: %v", err)
		}
		if total != 1 || len(rows) != 1 || rows[0].Host != "host%withpercent" {
			t.Fatalf("host percent filter total=%d rows=%v, want 1 host%%withpercent", total, rows)
		}
		// Host filter containing _ should not wildcard to X.
		rows, total, err = st.ListFindings(ctx, FindingFilter{ScanID: scanID, Host: "host_with"})
		if err != nil {
			t.Fatalf("list findings host _: %v", err)
		}
		if total != 1 || rows[0].Host != "host_with_underscore" {
			t.Fatalf("host underscore filter total=%d rows=%v, want underscore literal", total, rows)
		}
		// Ensure plain host without meta but substring still works: query "hostnormal" substring "host" should match multiple? Use general host "host" contains should match 5? But we test via ListFindings Host "host" substring.
		rows, total, err = st.ListFindings(ctx, FindingFilter{ScanID: scanID, Host: "host"})
		if err != nil {
			t.Fatalf("list findings host plain: %v", err)
		}
		if total != 5 {
			t.Fatalf("host plain substring total=%d, want 5", total)
		}
		// CVE field with percent
		ingestCVE := func(cves []string, template string) {
			f := types.NucleiFinding{TemplateID: template, Host: "like.test.invalid", MatchedAt: "https://like.test.invalid/" + template, Type: "http", Info: types.NucleiInfo{Name: template, Severity: "info", Classification: &types.NucleiClassification{CVEID: cves}}}
			raw, _ := json.Marshal(f)
			if err := st.IngestFinding(ctx, scanID, target.ID, f, raw); err != nil {
				t.Fatalf("ingest cve %v: %v", cves, err)
			}
		}
		// Need new scan for CVE to avoid mixing? Reuse same scan but distinct findings; list with CVE filter will search across all.
		ingestCVE([]string{"CVE-2021-%123"}, "tpl-cve-pct")
		ingestCVE([]string{"CVE-2021-123"}, "tpl-cve-normal")
		rows, total, err = st.ListFindings(ctx, FindingFilter{ScanID: scanID, CVE: "CVE-2021-%"})
		if err != nil {
			t.Fatalf("list findings CVE %%: %v", err)
		}
		if total != 1 {
			t.Fatalf("CVE percent filter total=%d, want 1, rows=%v", total, rows)
		}
		if rows[0].TemplateID != "tpl-cve-pct" {
			t.Fatalf("CVE percent matched wrong template: %v", rows[0])
		}
		// Query filter (name/template) with percent
		rows, total, err = st.ListFindings(ctx, FindingFilter{ScanID: scanID, Query: "tpl-a"})
		if err != nil {
			t.Fatalf("list findings query: %v", err)
		}
		if total != 1 || rows[0].TemplateID != "tpl-a" {
			t.Fatalf("query filter total=%d rows=%v, want tpl-a", total, rows)
		}
		// Backslash literal via host
		rows, total, err = st.ListFindings(ctx, FindingFilter{ScanID: scanID, Host: "host\\with"})
		if err != nil {
			t.Fatalf("list findings backslash: %v", err)
		}
		if total != 1 || rows[0].Host != "host\\with\\backslash" {
			t.Fatalf("backslash host filter total=%d rows=%v", total, rows)
		}
	})

	// --- Structured lifecycle filter via ListLifecycleFindings (ILIKE ANY default escape) ---
	t.Run("lifecycle ILIKE ANY via ListLifecycleFindings", func(t *testing.T) {
		target, err := st.CreateTarget(ctx, Target{Name: "like-lifecycle-target-" + types.NewID(), Hosts: []string{"lifecycle.test.invalid"}})
		if err != nil {
			t.Fatalf("create target: %v", err)
		}
		spec := types.ScanSpec{Targets: target.Hosts, Templates: types.TemplateSelector{TemplateIDs: []string{"tpl"}, TemplatesCommit: "test"}}
		scanID, err := st.CreateScan(ctx, spec, ScanLink{TargetID: target.ID})
		if err != nil {
			t.Fatalf("create scan: %v", err)
		}
		ingestLF := func(templateID, host string) {
			f := types.NucleiFinding{TemplateID: templateID, Host: host, MatchedAt: "https://lifecycle.test.invalid/" + templateID, Type: "http", Info: types.NucleiInfo{Name: templateID, Severity: "info"}}
			raw, _ := json.Marshal(f)
			if err := st.IngestFinding(ctx, scanID, target.ID, f, raw); err != nil {
				t.Fatalf("ingest lifecycle %s: %v", templateID, err)
			}
		}
		ingestLF("tpl-percent-%", "lifecycle.test.invalid")
		ingestLF("tpl-normal", "lifecycle.test.invalid")
		ingestLF("tpl-underscore-_", "host_with_underscore")
		// Need to complete scan for lifecycle to be visible? ListLifecycleFindings reads from finding_lifecycle + findings.
		// IngestFinding upserts lifecycle immediately, so we can query without MarkComplete.

		// Filter host contains literal % host - host we used is lifecycle.test.invalid for normal, but we need hosts containing %
		ingestLF("tpl-host-pct", "myhost%literal")
		ingestLF("tpl-host-normal2", "myhostXliteral")

		// Query host contains "%"
		q := FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "contains", Values: []string{"myhost%literal"}}}}}}
		rows, total, err := st.ListLifecycleFindings(ctx, q, 50, 0)
		if err != nil {
			t.Fatalf("list lifecycle host percent: %v", err)
		}
		if total != 1 {
			t.Fatalf("lifecycle host percent total=%d, want 1, rows=%v", total, rows)
		}
		if rows[0].Host != "myhost%literal" {
			t.Fatalf("lifecycle host percent matched wrong host: %v", rows[0])
		}
		// host contains underscore literal
		q = FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "host", Op: "contains", Values: []string{"host_with"}}}}}}
		rows, total, err = st.ListLifecycleFindings(ctx, q, 50, 0)
		if err != nil {
			t.Fatalf("list lifecycle underscore: %v", err)
		}
		foundUnderscore := false
		for _, r := range rows {
			if r.Host == "host_with_underscore" {
				foundUnderscore = true
			}
			if r.Host == "lifecycle.test.invalid" && r.TemplateID == "tpl-percent-%" {
				t.Fatalf("underscore query incorrectly matched percent host")
			}
		}
		if !foundUnderscore {
			t.Fatalf("lifecycle underscore query did not match, rows=%v", rows)
		}
		// name contains percent literal (template id)
		q = FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "name", Op: "contains", Values: []string{"tpl-percent-%"}}}}}}
		rows, total, err = st.ListLifecycleFindings(ctx, q, 50, 0)
		if err != nil {
			t.Fatalf("list lifecycle name percent: %v", err)
		}
		if total != 1 || rows[0].TemplateID != "tpl-percent-%" {
			t.Fatalf("lifecycle name percent total=%d rows=%v, want tpl-percent-%%", total, rows)
		}
		// cve contains - test via lifecycle cve array
		ingestLFCVE := func(templateID string, cves []string) {
			f := types.NucleiFinding{TemplateID: templateID, Host: "lifecycle.test.invalid", MatchedAt: "https://lifecycle.test.invalid/" + templateID, Type: "http", Info: types.NucleiInfo{Name: templateID, Severity: "info", Classification: &types.NucleiClassification{CVEID: cves}}}
			raw, _ := json.Marshal(f)
			if err := st.IngestFinding(ctx, scanID, target.ID, f, raw); err != nil {
				t.Fatalf("ingest lifecycle cve %v: %v", cves, err)
			}
		}
		ingestLFCVE("tpl-cve-pct-lc", []string{"CVE-%-123"})
		ingestLFCVE("tpl-cve-normal-lc", []string{"CVE-2021-123"})
		q = FindingQuery{Groups: []FindingGroup{{Conditions: []FindingCondition{{Field: "cve", Op: "contains", Values: []string{"CVE-%"}}}}}}
		rows, total, err = st.ListLifecycleFindings(ctx, q, 50, 0)
		if err != nil {
			t.Fatalf("list lifecycle cve percent: %v", err)
		}
		if total != 1 || rows[0].TemplateID != "tpl-cve-pct-lc" {
			t.Fatalf("lifecycle cve percent total=%d rows=%v, want tpl-cve-pct-lc", total, rows)
		}
	})
}
