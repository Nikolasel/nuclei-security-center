package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

const fullSHA = "3beec52abcdef0123456789abcdef0123456789ab"

func TestFormatDisplayString(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		commit  string
		wantTag string
		wantSHA string
		want    string
	}{
		{
			name:    "tagged release",
			tag:     "v0.5.0-beta",
			commit:  fullSHA,
			wantTag: "v0.5.0-beta",
			wantSHA: fullSHA,
			want:    "v0.5.0-beta (3beec52)",
		},
		{
			name:    "untagged keeps the commit and invents no tag",
			tag:     "",
			commit:  fullSHA,
			wantTag: "",
			wantSHA: fullSHA,
			want:    "dev (3beec52)",
		},
		{
			name:    "no vcs info",
			tag:     "",
			commit:  "",
			wantTag: "",
			wantSHA: "",
			want:    "dev (unknown)",
		},
		{
			name:    "devel pseudo-version never leaks",
			tag:     "(devel)",
			commit:  "(devel)",
			wantTag: "",
			wantSHA: "",
			want:    "dev (unknown)",
		},
		{
			name:    "devel word is not a tag",
			tag:     "devel",
			commit:  fullSHA,
			wantTag: "",
			wantSHA: fullSHA,
			want:    "dev (3beec52)",
		},
		{
			name:    "whitespace and uppercase sha",
			tag:     "  v1.2.3  ",
			commit:  "  " + strings.ToUpper(fullSHA) + "  ",
			wantTag: "v1.2.3",
			wantSHA: fullSHA,
			want:    "v1.2.3 (3beec52)",
		},
		{
			name:    "short sha is kept whole",
			tag:     "",
			commit:  "3beec52",
			wantTag: "",
			wantSHA: "3beec52",
			want:    "dev (3beec52)",
		},
		{
			name:    "non-hex commit is unknown",
			tag:     "v0.5.0-beta",
			commit:  "v0.0.0-20240924120000-" + fullSHA[:12],
			wantTag: "v0.5.0-beta",
			wantSHA: "",
			want:    "v0.5.0-beta (unknown)",
		},
		{
			name:    "too-short commit is unknown",
			tag:     "",
			commit:  "abc",
			wantTag: "",
			wantSHA: "",
			want:    "dev (unknown)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := format(tc.tag, tc.commit)
			if got.Tag != tc.wantTag || got.Commit != tc.wantSHA || got.Version != tc.want {
				t.Fatalf("format(%q, %q) = %+v, want tag %q commit %q version %q", tc.tag, tc.commit, got, tc.wantTag, tc.wantSHA, tc.want)
			}
			if strings.Contains(got.Version, "devel") || strings.Contains(got.Tag, "devel") || strings.Contains(got.Commit, "devel") {
				t.Fatalf("(devel) leaked into %+v", got)
			}
		})
	}
}

func TestCommitFromBuildInfoIgnoresDevelVersion(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: fullSHA},
		},
	}
	if got := commitFromBuildInfo(info); got != fullSHA {
		t.Fatalf("commit = %q, want %s", got, fullSHA)
	}
	display := format("", commitFromBuildInfo(info))
	if display.Version != "dev (3beec52)" {
		t.Fatalf("version = %q", display.Version)
	}
	if strings.Contains(display.Version, "devel") {
		t.Fatalf("(devel) leaked: %+v", display)
	}

	bare := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}
	if got := format("", commitFromBuildInfo(bare)); got.Version != "dev (unknown)" {
		t.Fatalf("version = %q, want dev (unknown)", got.Version)
	}
}

func TestCurrentPrefersLinkStamp(t *testing.T) {
	origTag, origCommit := versionTag, gitCommit
	t.Cleanup(func() {
		versionTag, gitCommit = origTag, origCommit
	})
	versionTag = "v0.5.0-beta"
	gitCommit = fullSHA

	got := Current()
	if got.Tag != "v0.5.0-beta" || got.Commit != fullSHA || got.Version != "v0.5.0-beta (3beec52)" {
		t.Fatalf("Current() = %+v", got)
	}
}

func TestCurrentUnstampedIsHonest(t *testing.T) {
	origTag, origCommit := versionTag, gitCommit
	t.Cleanup(func() {
		versionTag, gitCommit = origTag, origCommit
	})
	versionTag = ""
	gitCommit = ""

	got := Current()
	if got.Tag != "" {
		t.Fatalf("unstamped tag = %q, want empty", got.Tag)
	}
	if got.Version == "" || strings.Contains(got.Version, "devel") {
		t.Fatalf("version = %q", got.Version)
	}
	if !strings.HasPrefix(got.Version, "dev (") || !strings.HasSuffix(got.Version, ")") {
		t.Fatalf("version = %q, want dev (…)", got.Version)
	}
	if got.Commit == "" {
		if got.Version != "dev (unknown)" {
			t.Fatalf("version = %q, want dev (unknown)", got.Version)
		}
		return
	}
	if len(got.Commit) < shortLen || !strings.HasPrefix(got.Commit, got.Version[len("dev ("):len(got.Version)-1]) {
		t.Fatalf("display %q does not lead with commit %q", got.Version, got.Commit)
	}
}
