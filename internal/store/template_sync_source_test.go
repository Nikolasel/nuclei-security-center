package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestTemplateSyncSourceSeedsOncePostgres pins the seed-once contract (#343):
// the environment-derived repo/ref fill NULL columns exactly once; after that
// the stored values win and re-seeding with different env values changes
// nothing, while the admin update path overwrites both columns.
func TestTemplateSyncSourceSeedsOncePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	src, err := st.GetTemplateSyncSource(ctx)
	if err != nil {
		t.Fatalf("read unseeded template sync source: %v", err)
	}
	if src.Repo != "" || src.Ref != "" {
		t.Fatalf("unseeded template sync source = %+v, want empty", src)
	}

	const firstRepo = "https://github.com/projectdiscovery/nuclei-templates.git"
	seeded, err := st.SeedTemplateSyncSource(ctx, TemplateSyncSource{Repo: firstRepo, Ref: "latest"})
	if err != nil {
		t.Fatalf("seed template sync source: %v", err)
	}
	if seeded.Repo != firstRepo || seeded.Ref != "latest" {
		t.Fatalf("seeded source = %+v, want repo %q ref latest", seeded, firstRepo)
	}

	// A later env change must not win: the DB is the source of record.
	reseeded, err := st.SeedTemplateSyncSource(ctx, TemplateSyncSource{Repo: "https://example.test/fork.git", Ref: "main"})
	if err != nil {
		t.Fatalf("re-seed template sync source: %v", err)
	}
	if reseeded.Repo != firstRepo || reseeded.Ref != "latest" {
		t.Fatalf("re-seed overwrote stored source: %+v, want %q/latest", reseeded, firstRepo)
	}
	got, err := st.GetTemplateSyncSource(ctx)
	if err != nil {
		t.Fatalf("read template sync source after re-seed: %v", err)
	}
	if got.Repo != firstRepo || got.Ref != "latest" {
		t.Fatalf("stored template sync source = %+v, want %q/latest", got, firstRepo)
	}

	// The admin switch replaces both columns; an explicit empty repo is the
	// documented disabled state.
	updated, err := st.UpdateTemplateSyncSource(ctx, TemplateSyncSource{Repo: "https://user:secret@example.test/templates.git", Ref: "v9.9.9"})
	if err != nil {
		t.Fatalf("update template sync source: %v", err)
	}
	if updated.Repo != "https://user:secret@example.test/templates.git" || updated.Ref != "v9.9.9" {
		t.Fatalf("updated source = %+v, want credential-bearing repo and v9.9.9", updated)
	}
	updated, err = st.UpdateTemplateSyncSource(ctx, TemplateSyncSource{Repo: "", Ref: "latest"})
	if err != nil {
		t.Fatalf("update template sync source to disabled: %v", err)
	}
	if updated.Repo != "" || updated.Ref != "latest" {
		t.Fatalf("disabled source = %+v, want empty repo with latest", updated)
	}
}
