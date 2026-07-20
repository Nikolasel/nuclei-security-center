package backend

import (
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestParseCron(t *testing.T) {
	valid := []string{
		"* * * * *",
		"0 3 * * *",    // 03:00 daily
		"*/15 * * * *", // every 15 min
		"0 0 * * 0",    // Sundays midnight
		"@daily",
		"@hourly",
		"@every 30m",
	}
	for _, c := range valid {
		if _, err := parseCron(c); err != nil {
			t.Errorf("parseCron(%q) = %v, want nil", c, err)
		}
	}

	invalid := []string{
		"",
		"not a cron",
		"* * * *",    // too few fields
		"60 * * * *", // minute out of range
		"* * * * 8",  // day-of-week out of range
		"@every",     // missing duration
	}
	for _, c := range invalid {
		if _, err := parseCron(c); err == nil {
			t.Errorf("parseCron(%q) = nil, want error", c)
		}
	}
}

func TestNextRun(t *testing.T) {
	base := time.Date(2026, 7, 10, 1, 30, 0, 0, time.UTC)
	// "0 3 * * *" fires at 03:00; from 01:30 that's the same day 03:00.
	got, err := nextRun("0 3 * * *", base)
	if err != nil {
		t.Fatalf("nextRun error: %v", err)
	}
	want := time.Date(2026, 7, 10, 3, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("nextRun = %v, want %v", got, want)
	}
	// Next() is strictly after the argument: at exactly 03:00, the next fire is
	// the following day.
	got2, _ := nextRun("0 3 * * *", want)
	if !got2.After(want) {
		t.Errorf("nextRun(%v) = %v, want strictly after", want, got2)
	}
}

func TestScheduleNextRun(t *testing.T) {
	now := time.Date(2026, 7, 10, 1, 30, 0, 0, time.UTC)

	// Disabled → nil, regardless of cron.
	if got, err := scheduleNextRun("0 3 * * *", false, now); err != nil || got != nil {
		t.Errorf("scheduleNextRun(disabled) = (%v, %v), want (nil, nil)", got, err)
	}

	// Enabled → the next fire time.
	got, err := scheduleNextRun("0 3 * * *", true, now)
	if err != nil {
		t.Fatalf("scheduleNextRun(enabled) error: %v", err)
	}
	if got == nil || !got.Equal(time.Date(2026, 7, 10, 3, 0, 0, 0, time.UTC)) {
		t.Errorf("scheduleNextRun(enabled) = %v, want 2026-07-10 03:00", got)
	}

	// Enabled with a bad cron → error.
	if _, err := scheduleNextRun("nope", true, now); err == nil {
		t.Error("scheduleNextRun(bad cron, enabled) = nil error, want error")
	}
}

func TestValidateSchedule(t *testing.T) {
	ok := store.Schedule{Name: " nightly ", ScanPolicyID: " p1 ", Cron: " 0 3 * * * "}
	if err := validateSchedule(&ok); err != nil {
		t.Fatalf("validateSchedule(valid) = %v", err)
	}
	if ok.Name != "nightly" || ok.ScanPolicyID != "p1" || ok.Cron != "0 3 * * *" {
		t.Errorf("validateSchedule did not trim fields: %+v", ok)
	}

	bad := []store.Schedule{
		{Name: "", ScanPolicyID: "p1", Cron: "0 3 * * *"},   // no name
		{Name: "x", ScanPolicyID: "", Cron: "0 3 * * *"},    // no scan policy
		{Name: "x", ScanPolicyID: "p1", Cron: ""},           // no cron
		{Name: "x", ScanPolicyID: "p1", Cron: "not a cron"}, // bad cron
	}
	for _, s := range bad {
		s := s
		if err := validateSchedule(&s); err == nil {
			t.Errorf("validateSchedule(%+v) = nil, want error", s)
		}
	}
}

func TestCapDueSchedules(t *testing.T) {
	mk := func(n int) []store.Schedule {
		out := make([]store.Schedule, n)
		for i := range out {
			out[i] = store.Schedule{ID: string(rune('a' + i))}
		}
		return out
	}

	// Over the cap: truncated to exactly max, preserving order.
	over := mk(maxDispatchPerTick + 5)
	got := capDueSchedules(over, maxDispatchPerTick)
	if len(got) != maxDispatchPerTick {
		t.Errorf("len = %d, want %d", len(got), maxDispatchPerTick)
	}
	if got[0].ID != over[0].ID {
		t.Errorf("order not preserved: got[0]=%q want %q", got[0].ID, over[0].ID)
	}

	// At or under the cap: returned unchanged.
	under := mk(3)
	if len(capDueSchedules(under, maxDispatchPerTick)) != 3 {
		t.Error("under-cap slice should be returned in full")
	}
}
