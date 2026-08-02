package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestTemplateSetExclusionsPostgres exercises the migration, effective
// member count, read/write APIs, and the exact-set guardrail together against
// the real PostgreSQL schema. It is opt-in like the other store integration
// tests because ordinary unit runs do not require a database.
func TestTemplateSetExclusionsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn, "0038_dynamic_template_set_exclusions.sql")

	ids := []string{"dynamic-include-one", "dynamic-excluded", "dynamic-include-two"}
	for i, id := range ids {
		if _, err := st.pool.Exec(ctx,
			`INSERT INTO templates
			 (id, source, path, yaml, content_sha256, name, severity, availability)
			 VALUES ($1, 'custom', $2, $3, $4, $5, 'low', 'active')`,
			id, "custom/"+id+".yaml", "id: "+id+"\n", "sha-"+id, id,
		); err != nil {
			t.Fatalf("insert template %d: %v", i, err)
		}
	}

	set, err := st.CreateTemplateSet(ctx, TemplateSet{
		Name:                "exclude mode " + types.NewID(),
		Mode:                TemplateSetModeExclude,
		ExcludedTemplateIDs: []string{" dynamic-excluded "},
	})
	if err != nil {
		t.Fatalf("create exclude set: %v", err)
	}
	if set.MemberCount != 2 || set.ExclusionCount != 1 {
		t.Fatalf("created set counts = members:%d exclusions:%d, want 2/1", set.MemberCount, set.ExclusionCount)
	}

	members, err := st.ListTemplateSetMembers(ctx, set.ID)
	if err != nil {
		t.Fatalf("list effective members: %v", err)
	}
	if len(members) != 2 || members[0].ID == "dynamic-excluded" || members[1].ID == "dynamic-excluded" {
		t.Fatalf("effective members = %#v, want excluded id absent", members)
	}
	exclusions, err := st.ListTemplateSetExclusions(ctx, set.ID)
	if err != nil {
		t.Fatalf("list exclusions: %v", err)
	}
	if len(exclusions) != 1 || exclusions[0].ID != "dynamic-excluded" {
		t.Fatalf("exclusions = %#v, want dynamic-excluded", exclusions)
	}
	if err := st.DeleteCustomTemplate(ctx, "dynamic-excluded"); !errors.Is(err, ErrTemplateSetExclusionInUse) {
		t.Fatalf("delete excluded template = %v, want ErrTemplateSetExclusionInUse", err)
	}
	exclusions, err = st.ListTemplateSetExclusions(ctx, set.ID)
	if err != nil || len(exclusions) != 1 || exclusions[0].ID != "dynamic-excluded" {
		t.Fatalf("exclusions after blocked delete = %#v, err:%v", exclusions, err)
	}

	set, err = st.UpdateTemplateSet(ctx, set.ID, TemplateSet{
		Name:                set.Name,
		Mode:                TemplateSetModeExclude,
		ExcludedTemplateIDs: []string{"dynamic-include-one", "dynamic-include-two"},
	})
	if err != nil {
		t.Fatalf("update exclude mode: %v", err)
	}
	if set.MemberCount != 1 || set.ExclusionCount != 2 {
		t.Fatalf("updated set counts = members:%d exclusions:%d, want 1/2", set.MemberCount, set.ExclusionCount)
	}

	all, err := st.CreateTemplateSet(ctx, TemplateSet{
		Name: "all mode " + types.NewID(), Mode: TemplateSetModeAll,
	})
	if err != nil {
		t.Fatalf("create all set: %v", err)
	}
	if all.MemberCount != 3 || all.ExclusionCount != 0 {
		t.Fatalf("all set counts = members:%d exclusions:%d, want 3/0", all.MemberCount, all.ExclusionCount)
	}
	allMembers, err := st.ListTemplateSetMembers(ctx, all.ID)
	if err != nil {
		t.Fatalf("list all-mode members: %v", err)
	}
	if len(allMembers) != 3 {
		t.Fatalf("all-mode members = %d, want 3", len(allMembers))
	}

	exact, err := st.CreateTemplateSet(ctx, TemplateSet{
		Name:                "exact exclusions " + types.NewID(),
		ExcludedTemplateIDs: []string{"dynamic-excluded"},
	})
	if !errors.Is(err, ErrTemplateSetExclusionsUnsupported) || exact.ID != "" {
		t.Fatalf("exact create with exclusions = set:%+v err:%v, want ErrTemplateSetExclusionsUnsupported", exact, err)
	}
	exact, err = st.CreateTemplateSet(ctx, TemplateSet{
		Name: "exact set " + types.NewID(),
	})
	if err != nil {
		t.Fatalf("create exact set: %v", err)
	}
	if _, err := st.ReplaceTemplateSetExclusions(ctx, exact.ID, []string{"dynamic-excluded"}, "test"); !errors.Is(err, ErrTemplateSetExclusionsUnsupported) {
		t.Fatalf("replace exact exclusions = %v, want ErrTemplateSetExclusionsUnsupported", err)
	}
}
