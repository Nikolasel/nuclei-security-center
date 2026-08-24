package scanner

import (
	"testing"
)

func TestParseGOMEMLIMIT(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"1500MiB", 1500 << 20},
		{"1500mib", 1500 << 20}, // case-insensitive
		{"1GiB", 1 << 30},
		{"1gib", 1 << 30},
		{"2TiB", 2 << 40},
		{"1TiB", 1 << 40},
		{"512KiB", 512 << 10},
		{"100B", 100},
		{"100b", 100},
		{"1073741824", 1073741824}, // bare bytes
		{"  256MiB  ", 256 << 20},  // trimmed
	} {
		got, err := ParseGOMEMLIMIT(tc.in)
		if err != nil {
			t.Errorf("ParseGOMEMLIMIT(%q) err=%v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseGOMEMLIMIT(%q)=%d want %d", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{
		"",
		"   ",
		"0",
		"0MiB",
		"-1MiB",
		"-100",
		"abc",
		"10XB",
		"MiB",
	} {
		if _, err := ParseGOMEMLIMIT(bad); err == nil {
			t.Errorf("ParseGOMEMLIMIT(%q) expected error, got nil", bad)
		}
	}
}

func TestParseCgroupLimitValue(t *testing.T) {
	for _, tc := range []struct {
		in    string
		ok    bool
		value int64
	}{
		{"max", false, 0},
		{"", false, 0},
		{"  max  ", false, 0},
		{"2147483648", true, 2147483648}, // 2 GiB
		{" 2147483648 ", true, 2147483648},
		{"0", false, 0},
		{"-1", false, 0},
		{"9223372036854771712", false, 0},      // ~8 EiB v1 sentinel > 1<<62
		{"9223372036854775807", false, 0},      // max int64
		{"1152921504606846976", false, 0},      // 1 PiB threshold (>=1<<50)
		{"1099511627775", true, 1099511627775}, // just below 1 PiB
		{"notanumber", false, 0},
	} {
		v, ok := parseCgroupLimitValue(tc.in)
		if ok != tc.ok {
			t.Errorf("parseCgroupLimitValue(%q) ok=%v want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && v != tc.value {
			t.Errorf("parseCgroupLimitValue(%q)=%d want %d", tc.in, v, tc.value)
		}
	}
}

func TestGomemlimitFromCgroup(t *testing.T) {
	// 2 GiB cgroup ⇒ 75% = 1.5 GiB = 1536 MiB.
	if got := gomemlimitFromCgroup(2 << 30); got != 1536<<20 {
		t.Errorf("2 GiB cgroup => %d want %d", got, 1536<<20)
	}
	// Tiny cap floors at 64 MiB instead of 37 MiB (50 MiB cap *0.75).
	if got := gomemlimitFromCgroup(50 << 20); got != 64<<20 {
		t.Errorf("50 MiB cgroup => %d want %d", got, 64<<20)
	}
	// 85 MiB cap: 63.75 MiB → floored 63 MiB but floor lifts to 64 MiB.
	if got := gomemlimitFromCgroup(85 << 20); got != 64<<20 {
		t.Errorf("85 MiB cgroup => %d want %d", got, 64<<20)
	}
	// 8 GiB ⇒ 6 GiB.
	if got := gomemlimitFromCgroup(8 << 30); got != 6<<30 {
		t.Errorf("8 GiB cgroup => %d want %d", got, 6<<30)
	}
	// Truncation to MiB: 2147483649 (2 GiB+1) *0.75 = 1610612736.75 → 1610612736
	// floored to MiB = 1536 MiB exactly.
	if got := gomemlimitFromCgroup(2147483649); got != 1536<<20 {
		t.Errorf("2147483649 => %d want %d", got, 1536<<20)
	}
}
