// Package version is the backend build identity stamped into the binary.
//
// Release images set versionTag and gitCommit with -ldflags. Those values are
// empty for a local go build or an unstamped image; Current then uses the
// VCS revision the toolchain embedded, when it has one. A tag is only legitimate
// when the build was actually cut from it, so it is never taken from Go's
// module version. Go reports untagged checkouts as "(devel)", and that
// pseudo-version must not surface in the API, logs, or UI.
package version

import (
	"runtime/debug"
	"strings"
)

// Set at link time, for example:
//
//	-X github.com/Nikolasel/nuclei-security-center/internal/version.versionTag=v0.5.0-beta
//	-X github.com/Nikolasel/nuclei-security-center/internal/version.gitCommit=<40-char sha>
var (
	versionTag string
	gitCommit  string
)

const (
	untaggedLabel = "dev"
	unknownCommit = "unknown"
	shortLen      = 7
)

// Info is the build identity returned by GET /api/version and logged at startup.
// Tag is empty when the build was not cut from a tag. Commit is the full SHA,
// or empty when none is available. Version is the display string.
type Info struct {
	Tag     string `json:"tag"`
	Commit  string `json:"commit"`
	Version string `json:"version"`
}

// Current resolves the stamped identity, falling back to embedded VCS data.
func Current() Info {
	return format(versionTag, resolveCommit(gitCommit))
}

func resolveCommit(stamped string) string {
	if commit := normalizeCommit(stamped); commit != "" {
		return commit
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return commitFromBuildInfo(info)
}

// commitFromBuildInfo reads vcs.revision only. Main.Version is ignored because
// an untagged build sets it to "(devel)".
func commitFromBuildInfo(info *debug.BuildInfo) string {
	if info == nil {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return normalizeCommit(setting.Value)
		}
	}
	return ""
}

// format builds the display string. A release leads with its tag; every other
// build says "dev". The commit is always present in the display string, shortened
// to seven hex characters, or "unknown" when there is no SHA.
func format(tag, commit string) Info {
	tag = normalizeTag(tag)
	commit = normalizeCommit(commit)
	label := tag
	if label == "" {
		label = untaggedLabel
	}
	short := unknownCommit
	if commit != "" {
		short = commit
		if len(short) > shortLen {
			short = short[:shortLen]
		}
	}
	return Info{
		Tag:     tag,
		Commit:  commit,
		Version: label + " (" + short + ")",
	}
}

func normalizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" || tag == "(devel)" || strings.EqualFold(tag, "devel") {
		return ""
	}
	if len(tag) > 128 {
		return ""
	}
	for _, r := range tag {
		if !validTagRune(r) {
			return ""
		}
	}
	return tag
}

func validTagRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '.' || r == '_' || r == '-' || r == '+':
		return true
	default:
		return false
	}
}

func normalizeCommit(commit string) string {
	commit = strings.ToLower(strings.TrimSpace(commit))
	if len(commit) < shortLen || len(commit) > 64 {
		return ""
	}
	for _, r := range commit {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return commit
}
