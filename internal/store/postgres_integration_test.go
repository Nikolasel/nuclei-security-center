package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func openIsolatedPostgres(t *testing.T, ctx context.Context, dsn string) *Store {
	t.Helper()
	st, _ := openEmptyIsolatedPostgres(t, ctx, dsn)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate isolated test schema: %v", err)
	}
	return st
}

func openEmptyIsolatedPostgres(t *testing.T, ctx context.Context, dsn string) (*Store, string) {
	return openEmptyIsolatedPostgresWithRuntimeParams(t, ctx, dsn, nil)
}

func openEmptyIsolatedPostgresWithRuntimeParams(t *testing.T, ctx context.Context, dsn string, runtimeParams map[string]string) (*Store, string) {
	t.Helper()
	admin, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin store: %v", err)
	}
	t.Cleanup(admin.Close)

	schema := "nsc_test_" + strings.ReplaceAll(types.NewID(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	for key, value := range runtimeParams {
		cfg.ConnConfig.RuntimeParams[key] = value
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open isolated schema pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return &Store{pool: pool}, schema
}
