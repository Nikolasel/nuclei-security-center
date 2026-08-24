package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// cgroupV2Max is the path for cgroup v2 unified hierarchy.
const cgroupV2Max = "/sys/fs/cgroup/memory.max"

// cgroupV1Limit is the path for cgroup v1 memory limit.
const cgroupV1Limit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"

// cgroupV1Alt is a fallback path seen on some systemd setups.
const cgroupV1Alt = "/sys/fs/cgroup/memory.limit_in_bytes"

// maxCgroupLimitThreshold treats any limit above this as "no limit" (unlimited).
// 1 PiB is a safe threshold: legitimate container limits in this deployment are
//
//	2 GiB; the kernel's "no limit" sentinel is ~9 EiB (9223372036854771712).
const maxCgroupLimitThreshold = 1 << 50 // ~1 PiB

// parseCgroupLimitValue parses one cgroup limit string (e.g. contents of
// memory.max) into a limit. Returns (0, false) when the value means unlimited
// ("max", empty, sentinel, or above threshold). The bool indicates whether a
// concrete limit was found.
func parseCgroupLimitValue(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		if uv, uerr := strconv.ParseUint(s, 10, 64); uerr == nil {
			if uv > 1<<62 {
				return 0, false
			}
			v = int64(uv)
		} else {
			return 0, false
		}
	}
	if v <= 0 || v >= maxCgroupLimitThreshold {
		return 0, false
	}
	return v, true
}

// readCgroupLimit reads the container's memory limit from cgroup v2 or v1.
// Returns 0 when no limit is set (unlimited / "max") or files are absent.
func readCgroupLimit() (int64, error) {
	paths := []string{cgroupV2Max, cgroupV1Limit, cgroupV1Alt}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, err
		}
		if v, ok := parseCgroupLimitValue(string(data)); ok {
			return v, nil
		}
	}
	return 0, nil
}

// ParseGOMEMLIMIT parses a GOMEMLIMIT value into bytes. Accepts the forms Go
// itself accepts: bare bytes (e.g. "1073741824") and KiB/MiB/GiB/TiB with optional
// "B" (e.g. "1500MiB", "2GiB", "1TiB"). Case-insensitive, no space between
// number and unit. Empty = error.
//
// Retained for testing/reference only; ConfigureMemoryLimit intentionally does
// not call it for the explicit branch because the Go runtime has already
// applied GOMEMLIMIT at process startup.
func ParseGOMEMLIMIT(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty GOMEMLIMIT")
	}
	// Longest suffixes first so "MiB" is not mistaken for "B".
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"TiB", 1 << 40},
		{"GiB", 1 << 30},
		{"MiB", 1 << 20},
		{"KiB", 1 << 10},
		{"B", 1},
	}
	upper := strings.ToUpper(strings.TrimSpace(s))
	for _, suf := range suffixes {
		if strings.HasSuffix(upper, strings.ToUpper(suf.suffix)) {
			numStr := strings.TrimSpace(s[:len(s)-len(suf.suffix)])
			if numStr == "" {
				return 0, fmt.Errorf("invalid GOMEMLIMIT %q", s)
			}
			n, err := strconv.ParseInt(numStr, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid GOMEMLIMIT %q: %w", s, err)
			}
			if n <= 0 {
				return 0, fmt.Errorf("GOMEMLIMIT must be positive: %q", s)
			}
			return n * suf.mult, nil
		}
	}
	// No suffix: bare bytes.
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid GOMEMLIMIT %q: %w", s, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("GOMEMLIMIT must be positive: %q", s)
	}
	return n, nil
}

// gomemlimitFromCgroup derives the GOMEMLIMIT bytes (≈75% of the cgroup
// cap, truncated to MiB and floored at 64 MiB). Exported for testing; the
// caller handles the cgroup read and env/debug plumbing.
func gomemlimitFromCgroup(limit int64) int64 {
	gomemlimit := limit * 3 / 4
	if gomemlimit < 64<<20 {
		// Floor assumes a non-tiny cgroup (production is 2 GiB). A cap below
		// ~85 MiB would otherwise yield a GOMEMLIMIT above the cgroup limit,
		// defeating the protection — but such a tiny container is not a
		// supported deployment.
		gomemlimit = 64 << 20
	}
	return (gomemlimit >> 20) << 20
}

// ConfigureMemoryLimit sets GOMEMLIMIT for child processes (nuclei/naabu) and
// the current scanner process based on the container's cgroup memory limit.
// An explicit GOMEMLIMIT in the environment always wins; the Go runtime has
// already applied it at process start, so we just log and return. When no
// limit can be determined, it leaves the runtime's default (no soft limit).
func ConfigureMemoryLimit(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	// Explicit operator value wins. The runtime read and applied GOMEMLIMIT
	// before main started, so no re-parse or SetMemoryLimit is needed.
	if explicit := strings.TrimSpace(os.Getenv("GOMEMLIMIT")); explicit != "" {
		log.Info("GOMEMLIMIT explicitly set by operator; runtime already honored", "value", explicit)
		return
	}

	limit, err := readCgroupLimit()
	if err != nil {
		log.Warn("could not read cgroup memory limit; GOMEMLIMIT not set", "err", err)
		return
	}
	if limit == 0 {
		log.Info("no cgroup memory limit detected; GOMEMLIMIT not set")
		return
	}
	floored := gomemlimitFromCgroup(limit)
	mib := floored >> 20
	value := fmt.Sprintf("%dMiB", mib)
	_ = os.Setenv("GOMEMLIMIT", value)
	debug.SetMemoryLimit(floored)
	log.Info("set GOMEMLIMIT from cgroup limit", "cgroup_limit_bytes", limit, "gomemlimit_bytes", floored, "GOMEMLIMIT", value)
}
