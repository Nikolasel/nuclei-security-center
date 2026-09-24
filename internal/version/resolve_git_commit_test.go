package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveGitCommitScript(t *testing.T) {
	const (
		shaMain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		shaFeat = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	tests := []struct {
		name  string
		setup func(t *testing.T, gitDir string)
		want  string
	}{
		{
			name: "branch ref file",
			setup: func(t *testing.T, gitDir string) {
				writeGitFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/feature\n")
				writeGitFile(t, filepath.Join(gitDir, "refs", "heads", "feature"), shaFeat+"\n")
			},
			want: shaFeat,
		},
		{
			name: "detached HEAD",
			setup: func(t *testing.T, gitDir string) {
				writeGitFile(t, filepath.Join(gitDir, "HEAD"), shaMain+"\n")
			},
			want: shaMain,
		},
		{
			name: "packed-refs when the loose ref is absent",
			setup: func(t *testing.T, gitDir string) {
				writeGitFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
				writeGitFile(t, filepath.Join(gitDir, "packed-refs"), ""+
					"# pack-refs with: peeled fully-peeled sorted\n"+
					shaMain+" refs/heads/main\n"+
					"^cccccccccccccccccccccccccccccccccccccccc\n"+
					shaFeat+" refs/heads/feature\n")
			},
			want: shaMain,
		},
		{
			name: "loose ref wins over packed-refs",
			setup: func(t *testing.T, gitDir string) {
				writeGitFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/feature\n")
				writeGitFile(t, filepath.Join(gitDir, "refs", "heads", "feature"), shaFeat+"\n")
				writeGitFile(t, filepath.Join(gitDir, "packed-refs"), shaMain+" refs/heads/feature\n")
			},
			want: shaFeat,
		},
		{
			name: "missing git dir",
			setup: func(t *testing.T, gitDir string) {
				if err := os.RemoveAll(gitDir); err != nil {
					t.Fatal(err)
				}
			},
			want: "",
		},
		{
			name: "non-hex HEAD",
			setup: func(t *testing.T, gitDir string) {
				writeGitFile(t, filepath.Join(gitDir, "HEAD"), "not-a-commit\n")
			},
			want: "",
		},
		{
			name: "ref escape is ignored",
			setup: func(t *testing.T, gitDir string) {
				writeGitFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/../secrets\n")
				writeGitFile(t, filepath.Join(gitDir, "secrets"), shaMain+"\n")
			},
			want: "",
		},
		{
			name: "non-ref pointer is ignored",
			setup: func(t *testing.T, gitDir string) {
				writeGitFile(t, filepath.Join(gitDir, "HEAD"), "ref: HEAD\n")
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitDir := t.TempDir()
			tt.setup(t, gitDir)
			if got := resolveGitCommit(t, gitDir); got != tt.want {
				t.Fatalf("commit = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveGitCommitScriptMatchesCheckout(t *testing.T) {
	root := filepath.Join("..", "..")
	gitDir := filepath.Join(root, ".git")
	if _, err := os.Stat(filepath.Join(gitDir, "HEAD")); err != nil {
		t.Skip("checkout has no .git/HEAD")
	}
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skip("git rev-parse HEAD is unavailable")
	}
	want := strings.TrimSpace(string(out))
	if got := resolveGitCommit(t, gitDir); got != want {
		t.Fatalf("commit = %q, want git rev-parse HEAD %q", got, want)
	}
}

func resolveGitCommit(t *testing.T, gitDir string) string {
	t.Helper()
	cmd := exec.Command("sh", filepath.Join("..", "..", "deploy", "resolve_git_commit.sh"), gitDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve_git_commit.sh: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeGitFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
