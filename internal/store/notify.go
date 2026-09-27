package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Notification kinds stored on scan_notification_outbox.kind.
const (
	NotifyKindDigest = "digest"
	NotifyKindFailed = "failed"
)

// SeverityCounts is per-severity tally used in a scan digest mail.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Total is the sum of all severity buckets.
func (c SeverityCounts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// ScanDigestFinding is one New/Changed/Fixed row included in a digest payload.
type ScanDigestFinding struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	Severity   string `json:"severity"`
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched_at"`
}

// ScanDigestPayload is the derived delta recorded for a completed scan.
// Status is not stored on finding_lifecycle; this JSON is the only record.
type ScanDigestPayload struct {
	New      SeverityCounts      `json:"new"`
	Changed  SeverityCounts      `json:"changed"`
	Fixed    SeverityCounts      `json:"fixed"`
	Findings []ScanDigestFinding `json:"findings"`
}

// HasDelta reports whether the digest contains any mailable change.
func (p ScanDigestPayload) HasDelta() bool {
	return p.New.Total()+p.Changed.Total()+p.Fixed.Total() > 0
}

// ScanFailedPayload is recorded when a scan is marked failed (not cancelled).
type ScanFailedPayload struct {
	Reason string `json:"reason"`
}

// ClaimScanNotification marks the outbox row claimed and returns its payload.
// A missing row, or a row already claimed, returns ok=false and is not an error:
// that is the at-most-once gate across retries and restarts.
func (s *Store) ClaimScanNotification(ctx context.Context, scanID, kind string) (payload []byte, ok bool, err error) {
	err = s.pool.QueryRow(ctx,
		`UPDATE scan_notification_outbox
		    SET claimed_at = now()
		  WHERE scan_id = $1 AND kind = $2 AND claimed_at IS NULL
		  RETURNING payload`,
		scanID, kind,
	).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("claim scan notification: %w", err)
	}
	return payload, true, nil
}

// ParseScanDigestPayload decodes a digest outbox payload.
func ParseScanDigestPayload(raw []byte) (ScanDigestPayload, error) {
	var p ScanDigestPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return ScanDigestPayload{}, fmt.Errorf("parse scan digest payload: %w", err)
	}
	if p.Findings == nil {
		p.Findings = []ScanDigestFinding{}
	}
	return p, nil
}

// ParseScanFailedPayload decodes a failed-scan outbox payload.
func ParseScanFailedPayload(raw []byte) (ScanFailedPayload, error) {
	var p ScanFailedPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return ScanFailedPayload{}, fmt.Errorf("parse scan failed payload: %w", err)
	}
	return p, nil
}
