package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestServiceAccountsRoleDBConstraintPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openIsolatedPostgres(t, ctx, dsn)

	// Valid roles are accepted via the store API (which bypasses the HTTP
	// allowlist — the DB constraint is the backstop).
	for _, role := range []string{"viewer", "operator", "admin"} {
		t.Run("valid role "+role+" via CreateServiceAccount", func(t *testing.T) {
			sa, err := st.CreateServiceAccount(ctx, ServiceAccount{
				Name:        "role-check-" + role + "-" + types.NewID()[:8],
				Role:        role,
				TokenPrefix: "deadbeefcafe",
			}, "hash-"+role+"-"+types.NewID(), nil)
			if err != nil {
				t.Fatalf("CreateServiceAccount role=%q failed: %v", role, err)
			}
			if sa.Role != role {
				t.Fatalf("created role = %q, want %q", sa.Role, role)
			}
		})
	}

	// Sanity: existing rows still satisfy the constraint — List after valid
	// inserts should see at least the three we just created.
	if accts, err := st.ListServiceAccounts(ctx); err != nil {
		t.Fatalf("ListServiceAccounts after valid inserts: %v", err)
	} else if len(accts) < 3 {
		t.Fatalf("ListServiceAccounts count = %d, want >=3 valid rows", len(accts))
	}

	// Invalid roles must be rejected at the database level, even when the
	// application allowlist is bypassed. Use raw SQL to bypass any Go
	// validation and prove the CHECK fires.
	cases := []struct {
		name string
		role string
	}{
		{"superadmin", "superadmin"},
		{"empty", ""},
		{"Viewer capitalised", "Viewer"},
		{"ADMIN upper", "ADMIN"},
		{"leading space", " viewer"},
		{"trailing space", "viewer "},
		{"injection", "admin'; DROP TABLE service_accounts; --"},
		{"unknown", "auditor"},
	}
	for _, tc := range cases {
		t.Run("reject "+tc.name+" via SQL", func(t *testing.T) {
			_, err := st.pool.Exec(ctx,
				`INSERT INTO service_accounts (id, name, role, token_hash, token_prefix)
				 VALUES ($1, $2, $3, $4, $5)`,
				types.NewID(), "bad-"+tc.name+"-"+types.NewID()[:8], tc.role, "hash-bad-"+types.NewID(), "badprefix12")
			if err == nil {
				t.Fatalf("INSERT service_accounts role=%q succeeded, want CHECK violation", tc.role)
			}
			msg := err.Error()
			if !strings.Contains(msg, "service_accounts_role_check") && !strings.Contains(strings.ToLower(msg), "check") {
				t.Fatalf("INSERT role=%q error = %q, want CHECK violation (service_accounts_role_check)", tc.role, msg)
			}
		})
	}

	// Also via the store method — the store does not validate role, so the
	// DB must be the backstop.
	t.Run("reject superadmin via CreateServiceAccount hits CHECK", func(t *testing.T) {
		_, err := st.CreateServiceAccount(ctx, ServiceAccount{
			Name:        "role-check-bad-" + types.NewID()[:8],
			Role:        "superadmin",
			TokenPrefix: "badprefix12",
		}, "hash-bad-"+types.NewID(), nil)
		if err == nil {
			t.Fatal("CreateServiceAccount role=superadmin succeeded, want CHECK violation")
		}
		msg := err.Error()
		if !strings.Contains(msg, "service_accounts_role_check") && !strings.Contains(strings.ToLower(msg), "check") {
			t.Logf("CreateServiceAccount(superadmin) error = %q (expected CHECK violation)", msg)
			// Still a failure if no CHECK indication and no error at all; with an
			// error we accept any constraint-violation wording, but prefer the
			// named constraint for debuggability.
			if !strings.Contains(strings.ToLower(msg), "violates") && !strings.Contains(strings.ToLower(msg), "constraint") {
				t.Fatalf("CreateServiceAccount(superadmin) error = %q, want constraint violation", msg)
			}
		}
	})
}
