package backend

import (
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestTargetGroupRequestNormalize(t *testing.T) {
	req := targetGroupRequest{
		Name:      "  prod  ",
		TargetIDs: []string{"a", " a ", "", "b", "a"},
	}
	if err := req.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if req.Name != "prod" {
		t.Errorf("name = %q, want trimmed 'prod'", req.Name)
	}
	// Trimmed, de-duped, blanks dropped, order preserved.
	want := []string{"a", "b"}
	if len(req.TargetIDs) != len(want) {
		t.Fatalf("target_ids = %v, want %v", req.TargetIDs, want)
	}
	for i := range want {
		if req.TargetIDs[i] != want[i] {
			t.Errorf("target_ids[%d] = %q, want %q", i, req.TargetIDs[i], want[i])
		}
	}
}

func TestTargetGroupRequestNormalizeEmptyName(t *testing.T) {
	req := targetGroupRequest{Name: "   "}
	if err := req.normalize(); err == nil {
		t.Fatal("blank name should error")
	}
}

func TestValidateScheduleTargetVsGroup(t *testing.T) {
	cases := []struct {
		name    string
		sc      store.Schedule
		wantErr bool
	}{
		{"target only", store.Schedule{Name: "n", TargetID: "t", Cron: "@daily"}, false},
		{"group only", store.Schedule{Name: "n", TargetGroupID: "g", Cron: "@daily"}, false},
		{"neither", store.Schedule{Name: "n", Cron: "@daily"}, true},
		{"both", store.Schedule{Name: "n", TargetID: "t", TargetGroupID: "g", Cron: "@daily"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := c.sc
			err := validateSchedule(&sc)
			if (err != nil) != c.wantErr {
				t.Errorf("validateSchedule(%+v) err = %v, wantErr %v", c.sc, err, c.wantErr)
			}
		})
	}
}
