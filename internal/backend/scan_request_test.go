package backend

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestBuildScanSpecRequiresPolicyAndTarget(t *testing.T) {
	var server Server
	for _, tc := range []struct {
		name string
		req  createScanRequest
		want string
	}{
		{name: "missing policy", req: createScanRequest{TargetID: "target"}, want: "scan_policy_id is required"},
		{name: "missing target", req: createScanRequest{ScanPolicyID: "policy"}, want: "target_id is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := server.buildScanSpec(context.Background(), tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("buildScanSpec(%+v) error = %v, want %q", tc.req, err, tc.want)
			}
		})
	}
}

// TestBuildScanSpecRejectsUnapprovedTargetPostgres pins the scope guardrail at
// the request boundary: target_id is caller-controlled, but only a stored target
// may become a concrete scan spec. It is opt-in with the other PostgreSQL tests.
func TestBuildScanSpecRejectsUnapprovedTargetPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	templateSet, err := st.CreateTemplateSet(ctx, store.TemplateSet{
		Name:       "scope-guard-templates-" + types.NewID(),
		DynamicAll: true,
	})
	if err != nil {
		t.Fatalf("create template set: %v", err)
	}
	policy, err := st.CreateScanPolicy(ctx, store.ScanPolicy{
		Name:          "scope-guard-policy-" + types.NewID(),
		TemplateSetID: templateSet.ID,
	})
	if err != nil {
		t.Fatalf("create scan policy: %v", err)
	}

	forgedTargetID := types.NewID()
	server := Server{store: st}
	_, _, err = server.buildScanSpec(ctx, createScanRequest{
		ScanPolicyID: policy.ID,
		TargetID:     forgedTargetID,
	})
	if err == nil || !strings.Contains(err.Error(), `unknown target_id "`+forgedTargetID+`"`) {
		t.Fatalf("buildScanSpec with unapproved target error = %v, want unknown target_id", err)
	}
}

func TestResolveConfigSpecHonorsDynamicTemplateExclusionsPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)
	for _, id := range []string{"resolver-keep", "resolver-exclude"} {
		if _, err := st.CreateCustomTemplate(ctx, store.Template{
			ID: id, Path: "custom/" + id + ".yaml", YAML: "id: " + id + "\n",
			ContentSHA256: "sha-" + id, Name: id, Severity: "low",
		}); err != nil {
			t.Fatalf("insert template %q: %v", id, err)
		}
	}

	templateSet, err := st.CreateTemplateSet(ctx, store.TemplateSet{
		Name:                "resolver-dynamic-" + types.NewID(),
		DynamicAll:          true,
		ExcludedTemplateIDs: []string{"resolver-exclude"},
	})
	if err != nil {
		t.Fatalf("create dynamic template set: %v", err)
	}
	target, err := st.CreateTarget(ctx, store.Target{
		Name:  "resolver-target-" + types.NewID(),
		Hosts: []string{"resolver.invalid"},
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	server := Server{store: st}
	spec, _, err := server.resolveConfigSpec(ctx, target.ID, templateSet.ID)
	if err != nil {
		t.Fatalf("resolve dynamic config: %v", err)
	}
	if len(spec.Templates.TemplateIDs) != 1 || spec.Templates.TemplateIDs[0] != "resolver-keep" {
		t.Fatalf("resolved template ids = %v, want [resolver-keep]", spec.Templates.TemplateIDs)
	}

	if _, err := st.UpdateTemplateSet(ctx, templateSet.ID, store.TemplateSet{
		Name:                templateSet.Name,
		DynamicAll:          true,
		ExcludedTemplateIDs: []string{"resolver-keep", "resolver-exclude"},
	}); err != nil {
		t.Fatalf("exclude all dynamic templates: %v", err)
	}
	if _, _, err := server.resolveConfigSpec(ctx, target.ID, templateSet.ID); err == nil || !strings.Contains(err.Error(), "no active templates after exclusions") {
		t.Fatalf("fully excluded dynamic config error = %v, want fail-closed error", err)
	}
}

func openScanRequestTestStore(t *testing.T, ctx context.Context, dsn string) *store.Store {
	t.Helper()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL admin pool: %v", err)
	}
	t.Cleanup(admin.Close)

	schema := "nsc_backend_test_" + strings.ReplaceAll(types.NewID(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})

	st, err := store.Open(ctx, dsnWithSearchPath(t, dsn, schema))
	if err != nil {
		t.Fatalf("open isolated test store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate isolated test store: %v", err)
	}
	return st
}

func dsnWithSearchPath(t *testing.T, dsn, schema string) string {
	t.Helper()
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse PostgreSQL URL: %v", err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	return dsn + " search_path=" + schema
}
