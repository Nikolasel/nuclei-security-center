package backend

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

const maxDigestFindingsInMail = 100

type scanNotifyStore interface {
	ClaimScanNotification(ctx context.Context, scanID, kind string) (payload []byte, ok bool, err error)
	ListUnclaimedScanNotifications(ctx context.Context) ([]store.ScanNotificationRef, error)
	GetScan(ctx context.Context, id string) (store.ScanRow, error)
}

// ScanNotifier claims a scan's outbox row and sends mail. It is best-effort:
// send failures are logged and never change a scan's terminal state.
type ScanNotifier struct {
	store  scanNotifyStore
	sender MailSender
	base   string
	from   string
	to     []string
	log    *slog.Logger
}

// NewScanNotifier wires the outbox to SMTP. sender and store must be non-nil.
func NewScanNotifier(st scanNotifyStore, sender MailSender, baseURL, from string, to []string, log *slog.Logger) *ScanNotifier {
	return &ScanNotifier{
		store:  st,
		sender: sender,
		base:   strings.TrimRight(baseURL, "/"),
		from:   from,
		to:     append([]string(nil), to...),
		log:    log,
	}
}

// Notify claims (scan_id, kind) and sends if the payload is mailable.
// A second call, or a call after a previous claim, is a no-op.
func (n *ScanNotifier) Notify(ctx context.Context, scanID, kind string) error {
	if n == nil || n.sender == nil {
		return nil
	}
	raw, ok, err := n.store.ClaimScanNotification(ctx, scanID, kind)
	if err != nil {
		return err
	}
	if !ok {
		n.log.Info("scan notification skipped", "scan_id", scanID, "kind", kind, "reason", "already_claimed_or_absent")
		return nil
	}
	scan, scanErr := n.store.GetScan(ctx, scanID)
	if scanErr != nil {
		n.log.Warn("scan notification: load scan", "scan_id", scanID, "err", scanErr)
		n.log.Info("scan notification skipped", "scan_id", scanID, "kind", kind, "reason", "scan_load_failed")
		return nil
	}
	if !scan.NotifyEnabled {
		n.log.Info("scan notification skipped", "scan_id", scanID, "kind", kind, "reason", "notify_disabled")
		return nil
	}
	var msg MailMessage
	to := n.to
	if len(scan.NotifyRecipients) > 0 {
		to = append([]string(nil), scan.NotifyRecipients...)
	}
	if len(to) == 0 {
		n.log.Info("scan notification skipped", "scan_id", scanID, "kind", kind, "reason", "no_recipients")
		return nil
	}
	switch kind {
	case store.NotifyKindDigest:
		payload, err := store.ParseScanDigestPayload(raw)
		if err != nil {
			return err
		}
		if !payload.HasDelta() {
			n.log.Info("scan notification skipped", "scan_id", scanID, "kind", kind, "reason", "empty_delta")
			return nil
		}
		msg, err = composeDigestMail(n.base, scan, payload)
		if err != nil {
			return err
		}
	case store.NotifyKindFailed:
		payload, err := store.ParseScanFailedPayload(raw)
		if err != nil {
			return err
		}
		msg, err = composeFailedMail(n.base, scan, payload)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown scan notification kind %q", kind)
	}
	msg.From = n.from
	msg.To = to
	if err := n.sender.Send(ctx, msg); err != nil {
		n.log.Error("scan notification send failed", "scan_id", scanID, "kind", kind, "err", err)
		return err
	}
	n.log.Info("scan notification sent", "scan_id", scanID, "kind", kind, "subject", msg.Subject)
	return nil
}

// NotifyUnclaimed claims and sends every outbox row with claimed_at NULL.
// Already-claimed rows are not listed and are not resent. Empty digest
// payloads are claimed and skipped, matching Notify.
func (n *ScanNotifier) NotifyUnclaimed(ctx context.Context) error {
	if n == nil || n.sender == nil {
		return nil
	}
	refs, err := n.store.ListUnclaimedScanNotifications(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, ref := range refs {
		if err := n.Notify(ctx, ref.ScanID, ref.Kind); err != nil {
			n.log.Error("scan notification", "scan_id", ref.ScanID, "kind", ref.Kind, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func composeDigestMail(base string, scan store.ScanRow, p store.ScanDigestPayload) (MailMessage, error) {
	scanURL := joinURL(base, "/scans/"+scan.ID)
	title := "Scan result changes"
	if scan.TargetName != "" {
		title = "Scan result changes — " + scan.TargetName
	}
	subject := fmt.Sprintf("[NSC] %s: %d new, %d changed, %d fixed",
		shortScan(scan.ID), p.New.Total(), p.Changed.Total(), p.Fixed.Total())

	listed := p.Findings
	if len(listed) > maxDigestFindingsInMail {
		listed = listed[:maxDigestFindingsInMail]
	}
	extra := len(p.Findings) - len(listed)

	var text strings.Builder
	fmt.Fprintf(&text, "%s\nScan: %s\n", title, scanURL)
	if scan.ScanPolicyName != "" {
		fmt.Fprintf(&text, "Policy: %s\n", scan.ScanPolicyName)
	}
	text.WriteString("\n")
	writeCountsText(&text, "New", p.New)
	writeCountsText(&text, "Changed (resurfaced)", p.Changed)
	writeCountsText(&text, "Fixed", p.Fixed)
	text.WriteString("\nFindings:\n")
	for _, f := range listed {
		fmt.Fprintf(&text, "- [%s] %s %s  %s  %s\n  %s\n",
			strings.ToUpper(f.Status), f.Severity, f.TemplateID, f.Name, f.MatchedAt,
			joinURL(base, fmt.Sprintf("/findings/%d", f.ID)))
	}
	if extra > 0 {
		fmt.Fprintf(&text, "… and %d more (open the scan in NSC)\n", extra)
	}

	html, err := renderMailTemplate("digest.html", newDigestMailData(scan, base, title, subject, p, listed, extra))
	if err != nil {
		return MailMessage{}, err
	}
	return MailMessage{
		Subject: subject,
		Text:    text.String(),
		HTML:    html,
	}, nil
}

func composeFailedMail(base string, scan store.ScanRow, p store.ScanFailedPayload) (MailMessage, error) {
	scanURL := joinURL(base, "/scans/"+scan.ID)
	reason := p.Reason
	if reason == "" {
		reason = scan.Error
	}
	if reason == "" {
		reason = "scan failed"
	}
	subject := fmt.Sprintf("[NSC] Scan failed %s", shortScan(scan.ID))
	title := "Scan failed"
	if scan.TargetName != "" {
		title = "Scan failed — " + scan.TargetName
	}
	text := fmt.Sprintf("A scan failed.\nScan: %s\nReason: %s\n", scanURL, reason)
	html, err := renderMailTemplate("failed.html", newFailedMailData(scan, base, title, subject, reason))
	if err != nil {
		return MailMessage{}, err
	}
	return MailMessage{Subject: subject, Text: text, HTML: html}, nil
}

func writeCountsText(b *strings.Builder, label string, c store.SeverityCounts) {
	if c.Total() == 0 {
		return
	}
	fmt.Fprintf(b, "%s: critical=%d high=%d medium=%d low=%d info=%d unknown=%d (total %d)\n",
		label, c.Critical, c.High, c.Medium, c.Low, c.Info, c.Unknown, c.Total())
}

func joinURL(base, path string) string {
	if base == "" {
		return path
	}
	return base + path
}

func shortScan(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
