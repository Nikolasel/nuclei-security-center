package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestScheduleNameUniquenessUpgradePostgres starts at the pre-0039 schema and
// exercises the data migration: the old case-sensitive column UNIQUE (0007)
// allowed "Nightly scan" and "nightly scan" to coexist, so the migration must
// resolve such collisions before building the lower(name) unique index, and the
// store must reject new case-insensitive duplicates afterwards.
func TestScheduleNameUniquenessUpgradePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st := openIsolatedPostgres(t, ctx, dsn, "0038_dynamic_template_set_exclusions.sql")

	targetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO targets (id, name, hosts) VALUES ($1, 'schedule-name-target', ARRAY['sched.invalid'])`,
		targetID); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	templateSetID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO template_sets (id, name) VALUES ($1, 'schedule-name-templates')`,
		templateSetID); err != nil {
		t.Fatalf("insert template set: %v", err)
	}
	policyID := types.NewID()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO scan_policies (id, name, template_set_id) VALUES ($1, 'schedule-name-policy', $2)`,
		policyID, templateSetID); err != nil {
		t.Fatalf("insert scan policy: %v", err)
	}

	insertSchedule := func(name string, at time.Time) string {
		t.Helper()
		id := types.NewID()
		if _, err := st.pool.Exec(ctx,
			`INSERT INTO schedules (id, name, scan_policy_id, target_id, cron, enabled, next_run_at, created_at)
			 VALUES ($1, $2, $3, $4, '0 3 * * *', true, $5, $6)`,
			id, name, policyID, targetID, at.Add(time.Hour), at); err != nil {
			t.Fatalf("insert schedule %q: %v", name, err)
		}
		return id
	}

	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	keepID := insertSchedule("Nightly scan", base)                 // earliest → keeps its name
	dupID := insertSchedule("nightly scan", base.Add(time.Minute)) // later duplicate → renamed
	exactDupID := insertSchedule("NIGHTLY SCAN", base.Add(2*time.Minute))
	// A hand-suffixed name that the ranked rename will land on: dupID becomes
	// "nightly scan (2)", which collides byte-identically with this row. The
	// old case-sensitive constraint must already be dropped, or this seeded
	// (real-world) layout aborts the migration.
	takenNameID := insertSchedule("nightly scan (2)", base.Add(3*time.Minute))

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate through 0039: %v", err)
	}

	names := map[string]string{}
	rows, err := st.pool.Query(ctx, `SELECT id::text, name FROM schedules ORDER BY created_at, id`)
	if err != nil {
		t.Fatalf("list migrated schedules: %v", err)
	}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			t.Fatalf("scan migrated schedule: %v", err)
		}
		names[id] = name
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migrated schedules: %v", err)
	}

	if names[keepID] != "Nightly scan" {
		t.Fatalf("earliest schedule renamed: %q, want %q", names[keepID], "Nightly scan")
	}
	if names[dupID] != "nightly scan (2)" {
		t.Fatalf("first duplicate = %q, want %q", names[dupID], "nightly scan (2)")
	}
	if names[exactDupID] != "NIGHTLY SCAN (3)" {
		t.Fatalf("second duplicate = %q, want %q", names[exactDupID], "NIGHTLY SCAN (3)")
	}
	// dupID was seeded a minute earlier than this row, and ranking is purely
	// (created_at, id) — so the row that just acquired the generated name
	// outranks the pre-existing owner, and the cascade renames the original
	// " (2)" row, not dupID.
	if names[takenNameID] != "nightly scan (2) (2)" {
		t.Fatalf("hand-suffixed owner = %q, want %q", names[takenNameID], "nightly scan (2) (2)")
	}
	seen := map[string]bool{}
	for _, name := range names {
		key := strings.ToLower(name)
		if seen[key] {
			t.Fatalf("migrated schedules still collide case-insensitively: %v", names)
		}
		seen[key] = true
	}

	var indexDef string
	if err := st.pool.QueryRow(ctx,
		`SELECT indexdef FROM pg_indexes
		  WHERE schemaname = current_schema()
		    AND indexname = 'schedules_name_key'`,
	).Scan(&indexDef); err != nil {
		t.Fatalf("read schedules_name_key index: %v", err)
	}
	if !strings.Contains(indexDef, "lower(name)") {
		t.Fatalf("schedules_name_key index = %q, want lower(name)", indexDef)
	}

	var uniqueConstraintCount int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.table_constraints
		  WHERE table_schema = current_schema()
		    AND table_name = 'schedules'
		    AND constraint_type = 'UNIQUE'`,
	).Scan(&uniqueConstraintCount); err != nil {
		t.Fatalf("count schedule unique constraints: %v", err)
	}
	if uniqueConstraintCount != 0 {
		t.Fatalf("case-sensitive UNIQUE constraint still present, count = %d", uniqueConstraintCount)
	}

	// A case-insensitive duplicate must now fail at the store boundary, and a
	// fresh distinct name must still succeed.
	next := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	if _, err := st.CreateSchedule(ctx, Schedule{
		Name: "nightly scan", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 4 * * *", Enabled: true, NextRunAt: &next,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateSchedule(case duplicate) = %v, want ErrConflict", err)
	}
	if _, err := st.UpdateSchedule(ctx, keepID, Schedule{
		Name: "Nightly Scan (2)", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 5 * * *", Enabled: true, NextRunAt: &next,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateSchedule(into case duplicate) = %v, want ErrConflict", err)
	}
	created, err := st.CreateSchedule(ctx, Schedule{
		Name: "Another schedule", ScanPolicyID: policyID, TargetID: targetID,
		Cron: "0 6 * * *", Enabled: true, NextRunAt: &next,
	})
	if err != nil {
		t.Fatalf("CreateSchedule(distinct name) = %v", err)
	}
	if created.Name != "Another schedule" {
		t.Fatalf("created schedule name = %q, want %q", created.Name, "Another schedule")
	}
}
