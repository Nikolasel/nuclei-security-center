package store

import "testing"

func TestAppSettingsRetentionActive(t *testing.T) {
	days := func(n int) *int { return &n }
	cases := []struct {
		name string
		in   AppSettings
		want bool
	}{
		{"enabled with positive window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(30)}, true},
		{"disabled with window", AppSettings{RetentionEnabled: false, ScanRetentionDays: days(30)}, false},
		{"enabled but window unset", AppSettings{RetentionEnabled: true, ScanRetentionDays: nil}, false},
		{"enabled but zero window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(0)}, false},
		{"enabled but negative window", AppSettings{RetentionEnabled: true, ScanRetentionDays: days(-5)}, false},
		{"zero value", AppSettings{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.RetentionActive(); got != c.want {
				t.Errorf("RetentionActive() = %v, want %v", got, c.want)
			}
		})
	}
}
