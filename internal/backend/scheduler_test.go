package backend

import (
	"strings"
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
		"CRON_TZ=America/New_York 0 3 * * *",
		"TZ=UTC 0 3 * * *",
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
	got, err := nextRun("0 3 * * *", base, time.UTC)
	if err != nil {
		t.Fatalf("nextRun error: %v", err)
	}
	want := time.Date(2026, 7, 10, 3, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("nextRun = %v, want %v", got, want)
	}
	// Next() is strictly after the argument: at exactly 03:00, the next fire is
	// the following day.
	got2, _ := nextRun("0 3 * * *", want, time.UTC)
	if !got2.After(want) {
		t.Errorf("nextRun(%v) = %v, want strictly after", want, got2)
	}
}

func TestNextRunAmericaNewYorkDST(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	// US DST 2026 starts Sunday 8 March 02:00 EST → 03:00 EDT.
	// Saturday 7 March 03:00 is still EST (UTC-5) = 08:00 UTC.
	// Sunday 8 March 03:00 is EDT (UTC-4) = 07:00 UTC.
	satFrom := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC) // Friday noon UTC
	gotSat, err := nextRun("0 3 * * *", satFrom, loc)
	if err != nil {
		t.Fatalf("nextRun(pre-DST) error: %v", err)
	}
	wantSat := time.Date(2026, 3, 7, 3, 0, 0, 0, loc)
	if !gotSat.Equal(wantSat) {
		t.Errorf("nextRun(pre-DST) = %v, want %v", gotSat, wantSat)
	}

	sunFrom := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC) // Saturday noon UTC (after 03:00 EST)
	gotSun, err := nextRun("0 3 * * *", sunFrom, loc)
	if err != nil {
		t.Fatalf("nextRun(DST) error: %v", err)
	}
	wantSun := time.Date(2026, 3, 8, 3, 0, 0, 0, loc)
	if !gotSun.Equal(wantSun) {
		t.Errorf("nextRun(DST) = %v, want %v", gotSun, wantSun)
	}
	if gotSat.UTC().Hour() == gotSun.UTC().Hour() {
		t.Errorf("DST boundary should shift the UTC instant of 03:00 New York; got %s then %s",
			gotSat.UTC(), gotSun.UTC())
	}
}

func TestScheduleNextRun(t *testing.T) {
	now := time.Date(2026, 7, 10, 1, 30, 0, 0, time.UTC)

	// Disabled → nil, regardless of cron.
	if got, err := scheduleNextRun("0 3 * * *", "UTC", false, now); err != nil || got != nil {
		t.Errorf("scheduleNextRun(disabled) = (%v, %v), want (nil, nil)", got, err)
	}

	// Enabled → the next fire time.
	got, err := scheduleNextRun("0 3 * * *", "UTC", true, now)
	if err != nil {
		t.Fatalf("scheduleNextRun(enabled) error: %v", err)
	}
	if got == nil || !got.Equal(time.Date(2026, 7, 10, 3, 0, 0, 0, time.UTC)) {
		t.Errorf("scheduleNextRun(enabled) = %v, want 2026-07-10 03:00", got)
	}

	// Empty timezone is UTC.
	gotEmpty, err := scheduleNextRun("0 3 * * *", "", true, now)
	if err != nil {
		t.Fatalf("scheduleNextRun(empty tz) error: %v", err)
	}
	if gotEmpty == nil || !gotEmpty.Equal(*got) {
		t.Errorf("scheduleNextRun(empty tz) = %v, want %v", gotEmpty, got)
	}

	// Enabled with a bad cron → error.
	if _, err := scheduleNextRun("nope", "UTC", true, now); err == nil {
		t.Error("scheduleNextRun(bad cron, enabled) = nil error, want error")
	}

	if _, err := scheduleNextRun("0 3 * * *", "Not/AZone", true, now); err == nil {
		t.Error("scheduleNextRun(bad timezone) = nil error, want error")
	}
}

func TestValidateSchedule(t *testing.T) {
	ok := store.Schedule{Name: " nightly ", ScanPolicyID: " p1 ", TargetID: " t1 ", Cron: " 0 3 * * * ", Timezone: " America/New_York "}
	if err := validateSchedule(&ok); err != nil {
		t.Fatalf("validateSchedule(valid) = %v", err)
	}
	if ok.Name != "nightly" || ok.ScanPolicyID != "p1" || ok.TargetID != "t1" || ok.Cron != "0 3 * * *" || ok.Timezone != "America/New_York" {
		t.Errorf("validateSchedule did not trim fields: %+v", ok)
	}

	omitted := store.Schedule{Name: "x", ScanPolicyID: "p1", TargetID: "t1", Cron: "0 3 * * *"}
	if err := validateSchedule(&omitted); err != nil {
		t.Fatalf("validateSchedule(omitted tz) = %v", err)
	}
	if omitted.Timezone != "UTC" {
		t.Errorf("validateSchedule(omitted tz) Timezone = %q, want UTC", omitted.Timezone)
	}

	bad := []store.Schedule{
		{Name: "", ScanPolicyID: "p1", TargetID: "t1", Cron: "0 3 * * *"},   // no name
		{Name: "x", ScanPolicyID: "", TargetID: "t1", Cron: "0 3 * * *"},    // no scan policy
		{Name: "x", ScanPolicyID: "p1", TargetID: "", Cron: "0 3 * * *"},    // no target
		{Name: "x", ScanPolicyID: "p1", TargetID: "t1", Cron: ""},           // no cron
		{Name: "x", ScanPolicyID: "p1", TargetID: "t1", Cron: "not a cron"}, // bad cron
		{Name: "x", ScanPolicyID: "p1", TargetID: "t1", Cron: "0 3 * * *", Timezone: "Not/AZone"},
		{Name: "x", ScanPolicyID: "p1", TargetID: "t1", Cron: "0 3 * * *", Timezone: "Local"},
		{Name: "x", ScanPolicyID: "p1", TargetID: "t1", Cron: "CRON_TZ=America/New_York 0 3 * * *"},
		{Name: "x", ScanPolicyID: "p1", TargetID: "t1", Cron: "TZ=UTC 0 3 * * *", Timezone: "Europe/Paris"},
	}
	for _, s := range bad {
		s := s
		if err := validateSchedule(&s); err == nil {
			t.Errorf("validateSchedule(%+v) = nil, want error", s)
		}
	}

	prefixed := store.Schedule{Name: "x", ScanPolicyID: "p1", TargetID: "t1", Cron: "CRON_TZ=America/New_York 0 3 * * *"}
	err := validateSchedule(&prefixed)
	if err == nil {
		t.Fatal("validateSchedule(CRON_TZ prefix) = nil, want error")
	}
	if !strings.Contains(err.Error(), "timezone") || !strings.Contains(err.Error(), "America/New_York") {
		t.Errorf("validateSchedule(CRON_TZ prefix) = %v, want error pointing at timezone America/New_York", err)
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
