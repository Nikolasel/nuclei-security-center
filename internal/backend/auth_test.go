package backend

import (
	"reflect"
	"sort"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestSatisfies(t *testing.T) {
	cases := []struct {
		roles    []string
		required string
		want     bool
	}{
		{[]string{RoleAdmin}, RoleViewer, true},   // admin outranks viewer
		{[]string{RoleAdmin}, RoleOperator, true}, // admin outranks operator
		{[]string{RoleOperator}, RoleOperator, true},
		{[]string{RoleOperator}, RoleAdmin, false},  // operator can't delete
		{[]string{RoleViewer}, RoleOperator, false}, // viewer can't run scans
		{[]string{RoleViewer}, RoleViewer, true},
		{nil, RoleViewer, false},               // no roles -> denied
		{[]string{"bogus"}, RoleViewer, false}, // unknown role ranks 0
		{[]string{"bogus", RoleAdmin}, RoleAdmin, true},
	}
	for _, c := range cases {
		if got := satisfies(store.Identity{Roles: c.roles}, c.required); got != c.want {
			t.Errorf("satisfies(%v, %q) = %v, want %v", c.roles, c.required, got, c.want)
		}
	}
}

func TestMapRoles(t *testing.T) {
	a := &Authenticator{cfg: AuthConfig{
		RolesClaim: "groups",
		GroupRoles: map[string]string{
			"nsc-admin":    RoleAdmin,
			"nsc-operator": RoleOperator,
			"nsc-viewer":   RoleViewer,
		},
	}}

	// Array claim, mixed known/unknown, with a duplicate mapping target.
	got := a.mapRoles(map[string]any{
		"groups": []any{"nsc-operator", "unrelated", "nsc-viewer", "nsc-viewer"},
	})
	sort.Strings(got)
	want := []string{RoleOperator, RoleViewer}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mapRoles array = %v, want %v", got, want)
	}

	// Single string claim.
	if got := a.mapRoles(map[string]any{"groups": "nsc-admin"}); !reflect.DeepEqual(got, []string{RoleAdmin}) {
		t.Errorf("mapRoles string = %v, want [admin]", got)
	}

	// Missing claim -> no roles.
	if got := a.mapRoles(map[string]any{}); len(got) != 0 {
		t.Errorf("mapRoles missing = %v, want empty", got)
	}
}

func TestSafeReturnTo(t *testing.T) {
	ok := []string{"/dashboard", "/findings?scan_id=1"}
	for _, p := range ok {
		if safeReturnTo(p) != p {
			t.Errorf("safeReturnTo(%q) rejected a valid relative path", p)
		}
	}
	bad := []string{
		"", "//evil.com", "https://evil.com", "relative", "/",
		`/\evil.com`, `/\/evil.com`, `\/evil.com`, `\\evil.com`, `/\`,
	}
	for _, p := range bad {
		if safeReturnTo(p) != "" {
			t.Errorf("safeReturnTo(%q) = %q, want \"\" (open-redirect guard)", p, safeReturnTo(p))
		}
	}
}
