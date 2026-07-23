package backend

import (
	"os"
	"path/filepath"
	"testing"

	git "github.com/go-git/go-git/v5"
)

func TestReadTemplateCatalog(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "http"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "http", "example.yaml"), []byte("id: example\ninfo:\n  name: Example\n  severity: medium\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata.yml"), []byte("name: ignored\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, err := readTemplateCatalog(root)
	if err != nil {
		t.Fatalf("readTemplateCatalog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].ID != "example" || entries[0].Path != "http/example.yaml" || entries[0].YAML == "" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}
}

func TestReadTemplateCatalogRejectsBadTemplate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad.yaml"), []byte("id: bad\ninfo: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readTemplateCatalog(root); err == nil {
		t.Fatal("expected invalid template error")
	}
}

func TestSetTemplateRemoteHonorsConfigChanges(t *testing.T) {
	repo, err := git.PlainInit(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := setTemplateRemote(repo, "https://example.test/first.git"); err != nil {
		t.Fatalf("set initial remote: %v", err)
	}
	if err := setTemplateRemote(repo, "https://example.test/second.git"); err != nil {
		t.Fatalf("change remote: %v", err)
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		t.Fatal(err)
	}
	if got := remote.Config().URLs; len(got) != 1 || got[0] != "https://example.test/second.git" {
		t.Errorf("origin URLs = %v", got)
	}
}
