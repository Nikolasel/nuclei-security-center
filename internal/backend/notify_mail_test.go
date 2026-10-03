package backend

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Golden files for the rendered mail documents live under
// testdata/mail/. Regenerate them after a deliberate template change with
// NSC_MAIL_GOLDEN_UPDATE=1 go test ./internal/backend/ -run 'MailGolden'.
const goldenEnv = "NSC_MAIL_GOLDEN_UPDATE"

func goldenMail(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "mail", name)
	if os.Getenv(goldenEnv) != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (set %s=1 to write it)", path, err, goldenEnv)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("rendered %s differs from the golden file; set %s=1 to refresh it", path, goldenEnv)
	}
}

func digestFixtureScan() store.ScanRow {
	return store.ScanRow{
		ID:             "6f0c2a1e-9b7d-4f3a-8c2d-1e0b5a9d7f3e",
		TargetName:     "prod-web",
		ScanPolicyName: "Weekly full scan",
		NotifyEnabled:  true,
	}
}

func digestFixturePayload() store.ScanDigestPayload {
	return store.ScanDigestPayload{
		New:     store.SeverityCounts{Critical: 1, High: 4, Medium: 2, Low: 3, Info: 25},
		Changed: store.SeverityCounts{Medium: 1, Unknown: 1},
		Fixed:   store.SeverityCounts{High: 1, Low: 2},
		Findings: []store.ScanDigestFinding{
			{ID: 101, Status: "new", Severity: "critical", TemplateID: "cve-2026-1234", Name: "Remote code execution in upload handler", MatchedAt: "https://prod-web.internal/upload"},
			{ID: 102, Status: "new", Severity: "high", TemplateID: "exposed-panels", Name: "Exposed admin panel", MatchedAt: "https://prod-web.internal/admin"},
			{ID: 103, Status: "new", Severity: "low", TemplateID: "missing-hsts", Name: "Missing HSTS header", MatchedAt: "https://prod-web.internal/"},
			{ID: 104, Status: "changed", Severity: "unknown", TemplateID: "tech-detect", Name: "Technology stack detection", MatchedAt: "https://prod-web.internal/"},
			{ID: 105, Status: "fixed", Severity: "high", TemplateID: "cve-2025-9999", Name: "Outdated nginx version", MatchedAt: "https://prod-web.internal/server-info"},
		},
	}
}

func TestDigestMailGolden(t *testing.T) {
	msg, err := composeDigestMail("https://nsc.example", digestFixtureScan(), digestFixturePayload())
	if err != nil {
		t.Fatal(err)
	}
	goldenMail(t, "digest.golden.html", []byte(msg.HTML))
}

func TestFailedMailGolden(t *testing.T) {
	scan := digestFixtureScan()
	msg, err := composeFailedMail("https://nsc.example", scan, store.ScanFailedPayload{
		Reason: "scanner node reported failure: nuclei exited with code 1\nlog tail: SIGSEGV in template executor",
	})
	if err != nil {
		t.Fatal(err)
	}
	goldenMail(t, "failed.golden.html", []byte(msg.HTML))
}

func TestDigestMailLinksAndCounts(t *testing.T) {
	msg, err := composeDigestMail("https://nsc.example", digestFixtureScan(), digestFixturePayload())
	if err != nil {
		t.Fatal(err)
	}
	html := msg.HTML
	for _, want := range []string{
		`href="https://nsc.example/scans/6f0c2a1e-9b7d-4f3a-8c2d-1e0b5a9d7f3e"`,
		`href="https://nsc.example/findings/101"`,
		`href="https://nsc.example/findings/105"`,
		">Open scan</a>",
		"Scan result changes — prod-web",
		"Policy: Weekly full scan",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("digest HTML missing %q", want)
		}
	}
	// Severity hierarchy: non-zero count cells carry their severity color,
	// zero cells are muted; chips carry the Badge/SeverityBadge tones.
	for _, want := range []string{
		"color:#b91c1c",            // critical counts
		"color:#c2410c",            // high counts
		"color:#a3a3a3",            // muted zero cells
		"background-color:#e0e7ff", // New chip
		"background-color:#dcfce7", // Fixed chip
		"background-color:#fee2e2", // critical severity chip
	} {
		if !strings.Contains(html, want) {
			t.Errorf("digest HTML missing style %q", want)
		}
	}
	// The Unknown bucket stays visible as a counts column and chip tone.
	if !strings.Contains(html, ">Unknown</th>") {
		t.Errorf("digest HTML missing Unknown counts column")
	}
	if !strings.Contains(html, ">unknown</span>") {
		t.Errorf("digest HTML missing unknown severity chip")
	}
}

func TestDigestMailCapsFindingsAndLinksRemainder(t *testing.T) {
	payload := store.ScanDigestPayload{New: store.SeverityCounts{Info: 102}}
	for i := range 102 {
		payload.Findings = append(payload.Findings, store.ScanDigestFinding{
			ID: 1000 + int64(i), Status: "new", Severity: "info",
			TemplateID: fmt.Sprintf("tpl-%d", i), Name: "Finding", MatchedAt: "https://h/",
		})
	}
	msg, err := composeDigestMail("https://nsc.example", digestFixtureScan(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(msg.HTML, `href="https://nsc.example/findings/`); got != maxDigestFindingsInMail {
		t.Errorf("finding links = %d, want %d (cap)", got, maxDigestFindingsInMail)
	}
	if !strings.Contains(msg.HTML, "View 2 more findings in the scan") {
		t.Errorf("digest HTML missing remainder link: %s", tail(msg.HTML, 300))
	}
	// The text fallback stays capped the same way.
	if !strings.Contains(msg.Text, "… and 2 more (open the scan in NSC)") {
		t.Errorf("digest text missing remainder note: %s", tail(msg.Text, 200))
	}
}

func TestDigestMailEmptyListKeepsScanLink(t *testing.T) {
	payload := store.ScanDigestPayload{New: store.SeverityCounts{High: 1}}
	msg, err := composeDigestMail("https://nsc.example", digestFixtureScan(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.HTML, "Open the scan to see the details.") {
		t.Errorf("empty-list fallback missing: %s", tail(msg.HTML, 300))
	}
}

func TestFailedMailReasonAndLink(t *testing.T) {
	scan := digestFixtureScan()
	msg, err := composeFailedMail("https://nsc.example", scan, store.ScanFailedPayload{Reason: "node down"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`href="https://nsc.example/scans/6f0c2a1e-9b7d-4f3a-8c2d-1e0b5a9d7f3e"`,
		">Reason</div>",
		"node down",
		"Scan failed — prod-web",
		"No presigned URLs.",
	} {
		if !strings.Contains(msg.HTML, want) {
			t.Errorf("failed HTML missing %q", want)
		}
	}
	// No digest table in the failure variant.
	if strings.Contains(msg.HTML, ">Counts</h2>") {
		t.Errorf("failed HTML must not carry the digest counts table")
	}
}

func TestMailHTMLHasNoExternalResources(t *testing.T) {
	base := "https://nsc.example"
	digest, err := composeDigestMail(base, digestFixtureScan(), digestFixturePayload())
	if err != nil {
		t.Fatal(err)
	}
	failed, err := composeFailedMail(base, digestFixtureScan(), store.ScanFailedPayload{Reason: "node down"})
	if err != nil {
		t.Fatal(err)
	}
	for name, html := range map[string]string{"digest": digest.HTML, "failed": failed.HTML} {
		for _, banned := range []string{"url(", "@import", "<link"} {
			if strings.Contains(html, banned) {
				t.Errorf("%s mail contains %q; mails must load no external resources", name, banned)
			}
		}
		// The only allowed src is the inline CID logo; anything else would be
		// a network fetch (remote image) or a broken reference.
		for _, m := range regexp.MustCompile(`src="([^"]*)"`).FindAllStringSubmatch(html, -1) {
			if m[1] != mailLogoCID {
				t.Errorf("%s mail has a non-inline src %q; only %q may load", name, m[1], mailLogoCID)
			}
		}
		for _, m := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(html, -1) {
			if !strings.HasPrefix(m[1], base) {
				t.Errorf("%s mail has a non-app link %q", name, m[1])
			}
		}
	}
}

func TestMailCarriesInlineLogo(t *testing.T) {
	digest, err := composeDigestMail("https://nsc.example", digestFixtureScan(), digestFixturePayload())
	if err != nil {
		t.Fatal(err)
	}
	failed, err := composeFailedMail("https://nsc.example", digestFixtureScan(), store.ScanFailedPayload{Reason: "node down"})
	if err != nil {
		t.Fatal(err)
	}
	pngMagic := []byte("\x89PNG\r\n\x1a\n")
	for name, msg := range map[string]MailMessage{"digest": digest, "failed": failed} {
		if len(msg.InlineImages) != 1 {
			t.Fatalf("%s mail carries %d inline images, want 1", name, len(msg.InlineImages))
		}
		img := msg.InlineImages[0]
		if img.Name != "nuclei-logo.png" {
			t.Errorf("%s mail inline image name = %q", name, img.Name)
		}
		if !bytes.HasPrefix(img.Data, pngMagic) {
			t.Errorf("%s mail inline image is not a PNG", name)
		}
		if !strings.Contains(msg.HTML, `src="`+mailLogoCID+`"`) {
			t.Errorf("%s mail HTML does not reference %s", name, mailLogoCID)
		}
		if !strings.Contains(msg.HTML, `width="36" height="36"`) {
			t.Errorf("%s mail logo lacks fixed dimensions", name)
		}
	}
}

func TestMailHTMLEscapesUntrustedValues(t *testing.T) {
	scan := store.ScanRow{ID: "abc", TargetName: `prod & <b>co</b>`, ScanPolicyName: `"quoted" & <policy>`}
	payload := store.ScanDigestPayload{
		New: store.SeverityCounts{Critical: 1},
		Findings: []store.ScanDigestFinding{
			{ID: 7, Status: "new", Severity: "critical",
				TemplateID: `<script>alert(1)</script>`, Name: `x&y "z"`, MatchedAt: `https://h/<p>?a=1&b=2`},
		},
	}
	msg, err := composeDigestMail("https://nsc.example", scan, payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.HTML, "<script>alert(1)</script>") {
		t.Errorf("raw script tag survived rendering: %s", tail(msg.HTML, 300))
	}
	if !strings.Contains(msg.HTML, "&lt;script&gt;") {
		t.Errorf("script tag was not entity-escaped in text context")
	}
	if !strings.Contains(msg.HTML, "prod &amp; &lt;b&gt;co&lt;/b&gt;") {
		t.Errorf("target name was not escaped: %s", tail(msg.HTML, 300))
	}
	failed, err := composeFailedMail("https://nsc.example", scan, store.ScanFailedPayload{Reason: "<img onerror=x>"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(failed.HTML, "<img onerror=x>") {
		t.Errorf("raw reason markup survived rendering")
	}
	if !strings.Contains(failed.HTML, "&lt;img onerror=x&gt;") {
		t.Errorf("reason was not escaped")
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
