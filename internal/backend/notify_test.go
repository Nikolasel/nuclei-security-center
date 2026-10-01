package backend

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

type recordingSender struct {
	mu   sync.Mutex
	msgs []MailMessage
	err  error
}

func (r *recordingSender) Send(_ context.Context, msg MailMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.msgs = append(r.msgs, msg)
	return nil
}

func (r *recordingSender) subjects() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.msgs))
	for i, m := range r.msgs {
		out[i] = m.Subject
	}
	return out
}

type fakeNotifyStore struct {
	payloads map[string][]byte
	claimed  map[string]bool
	scan     store.ScanRow
}

func (f *fakeNotifyStore) ClaimScanNotification(_ context.Context, scanID, kind string) ([]byte, bool, error) {
	key := scanID + "/" + kind
	if f.claimed[key] {
		return nil, false, nil
	}
	raw, ok := f.payloads[key]
	if !ok {
		return nil, false, nil
	}
	if f.claimed == nil {
		f.claimed = map[string]bool{}
	}
	f.claimed[key] = true
	return raw, true, nil
}

func (f *fakeNotifyStore) GetScan(_ context.Context, id string) (store.ScanRow, error) {
	if f.scan.ID == "" {
		return store.ScanRow{ID: id}, nil
	}
	return f.scan, nil
}

func (f *fakeNotifyStore) ListUnclaimedScanNotifications(_ context.Context) ([]store.ScanNotificationRef, error) {
	var out []store.ScanNotificationRef
	for key := range f.payloads {
		if f.claimed[key] {
			continue
		}
		scanID, kind, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		out = append(out, store.ScanNotificationRef{ScanID: scanID, Kind: kind})
	}
	return out, nil
}

func TestScanNotifierEmptyDeltaDoesNotSend(t *testing.T) {
	raw, _ := json.Marshal(store.ScanDigestPayload{})
	st := &fakeNotifyStore{payloads: map[string][]byte{"s1/" + store.NotifyKindDigest: raw}}
	sender := &recordingSender{}
	n := NewScanNotifier(st, sender, "http://nsc.example", "nsc@example", []string{"ops@example"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := n.Notify(context.Background(), "s1", store.NotifyKindDigest); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if got := sender.subjects(); len(got) != 0 {
		t.Fatalf("sent %v, want none for empty delta", got)
	}
}

func TestScanNotifierAtMostOnce(t *testing.T) {
	payload := store.ScanDigestPayload{
		New:      store.SeverityCounts{Critical: 1},
		Findings: []store.ScanDigestFinding{{ID: 7, Status: "new", Severity: "critical", TemplateID: "t", Name: "n", MatchedAt: "https://h"}},
	}
	raw, _ := json.Marshal(payload)
	st := &fakeNotifyStore{payloads: map[string][]byte{"s1/" + store.NotifyKindDigest: raw}}
	sender := &recordingSender{}
	n := NewScanNotifier(st, sender, "http://nsc.example", "nsc@example", []string{"ops@example"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := n.Notify(context.Background(), "s1", store.NotifyKindDigest); err != nil {
		t.Fatalf("first notify: %v", err)
	}
	if err := n.Notify(context.Background(), "s1", store.NotifyKindDigest); err != nil {
		t.Fatalf("second notify: %v", err)
	}
	if got := sender.subjects(); len(got) != 1 {
		t.Fatalf("sent %d mails, want 1", len(got))
	}
}

func TestScanNotifierSendFailureStillClaims(t *testing.T) {
	payload := store.ScanDigestPayload{
		New:      store.SeverityCounts{High: 2},
		Findings: []store.ScanDigestFinding{{ID: 1, Status: "new", Severity: "high", TemplateID: "t"}},
	}
	raw, _ := json.Marshal(payload)
	st := &fakeNotifyStore{payloads: map[string][]byte{"s1/" + store.NotifyKindDigest: raw}}
	sender := &recordingSender{err: errors.New("smtp down")}
	n := NewScanNotifier(st, sender, "http://nsc.example", "nsc@example", []string{"ops@example"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := n.Notify(context.Background(), "s1", store.NotifyKindDigest); err == nil {
		t.Fatal("expected send error")
	}
	sender.err = nil
	if err := n.Notify(context.Background(), "s1", store.NotifyKindDigest); err != nil {
		t.Fatalf("retry notify: %v", err)
	}
	if got := sender.subjects(); len(got) != 0 {
		t.Fatalf("failed send must not retry; got %v", got)
	}
}

func TestComposeDigestMailCountsAndLinks(t *testing.T) {
	msg := composeDigestMail("http://nsc.example", store.ScanRow{ID: "abc", TargetName: "prod"}, store.ScanDigestPayload{
		New:     store.SeverityCounts{Critical: 1, Info: 1},
		Changed: store.SeverityCounts{High: 1},
		Fixed:   store.SeverityCounts{Low: 2},
		Findings: []store.ScanDigestFinding{
			{ID: 42, Status: "new", Severity: "critical", TemplateID: "cve-1", Name: "RCE", MatchedAt: "https://h/path"},
		},
	})
	if !strings.Contains(msg.Subject, "2 new, 1 changed, 2 fixed") {
		t.Errorf("subject = %q", msg.Subject)
	}
	if !strings.Contains(msg.Text, "http://nsc.example/scans/abc") {
		t.Errorf("text missing scan link: %s", msg.Text)
	}
	if !strings.Contains(msg.Text, "http://nsc.example/findings/42") {
		t.Errorf("text missing finding link: %s", msg.Text)
	}
	if !strings.Contains(msg.HTML, "Changed") || !strings.Contains(msg.HTML, "Fixed") || !strings.Contains(msg.HTML, "Unknown") {
		t.Errorf("html missing buckets: %s", msg.HTML)
	}
}

func TestSMTPConfigFromEnvDisabled(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_FROM", "a@b")
	t.Setenv("SMTP_TO", "c@d")
	cfg, err := SMTPConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "" {
		t.Fatalf("host = %q, want unset", cfg.Host)
	}
	sender, err := NewSMTPSender(cfg)
	if err != nil || sender != nil {
		t.Fatalf("sender = %v err = %v, want nil,nil", sender, err)
	}
}

func TestScanNotifierNotifyUnclaimedSendsOnce(t *testing.T) {
	digest, _ := json.Marshal(store.ScanDigestPayload{
		New: store.SeverityCounts{Unknown: 1},
		Findings: []store.ScanDigestFinding{
			{ID: 1, Status: "new", Severity: "unknown", TemplateID: "t"},
		},
	})
	failed, _ := json.Marshal(store.ScanFailedPayload{Reason: "orphaned"})
	st := &fakeNotifyStore{payloads: map[string][]byte{
		"s1/" + store.NotifyKindDigest: digest,
		"s2/" + store.NotifyKindFailed: failed,
	}}
	st.claimed = map[string]bool{"s1/" + store.NotifyKindDigest: true}
	sender := &recordingSender{}
	n := NewScanNotifier(st, sender, "http://nsc.example", "nsc@example", []string{"ops@example"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := n.NotifyUnclaimed(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := sender.subjects(); len(got) != 1 || !strings.Contains(got[0], "failed") {
		t.Fatalf("sent %v, want only the unclaimed failed mail", got)
	}
	if err := n.NotifyUnclaimed(context.Background()); err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if got := sender.subjects(); len(got) != 1 {
		t.Fatalf("second drain resent: %v", got)
	}
}

func TestScanDigestPayloadHasDelta(t *testing.T) {
	if (store.ScanDigestPayload{}).HasDelta() {
		t.Fatal("empty payload must not have a delta")
	}
	if !(store.ScanDigestPayload{Changed: store.SeverityCounts{Medium: 1}}).HasDelta() {
		t.Fatal("changed count is a delta")
	}
	if !(store.ScanDigestPayload{New: store.SeverityCounts{Unknown: 1}}).HasDelta() {
		t.Fatal("unknown severity count is a delta")
	}
}
