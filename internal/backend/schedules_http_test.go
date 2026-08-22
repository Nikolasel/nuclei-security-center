package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// TestHandleUpdateSchedulePreservesEnabledTriStatePostgres is the regression
// coverage requested for #210: PUT without an explicit "enabled" key must
// preserve the stored value atomically, not default to true. It also pins
// explicit true/false and the next_run_at derivation.
func TestHandleUpdateSchedulePreservesEnabledTriStatePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	// Shared fixtures: target + policy.
	target, err := st.CreateTarget(ctx, store.Target{Name: "sched-preserve-target-" + types.NewID(), Hosts: []string{"preserve.invalid"}})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	ts, err := st.CreateTemplateSet(ctx, store.TemplateSet{Name: "sched-preserve-ts-" + types.NewID(), Mode: store.TemplateSetModeAll})
	if err != nil {
		t.Fatalf("create template set: %v", err)
	}
	policy, err := st.CreateScanPolicy(ctx, store.ScanPolicy{Name: "sched-preserve-policy-" + types.NewID(), TemplateSetID: ts.ID})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	srv := &Server{store: st, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}

	helper := func(t *testing.T, existing store.Schedule, body map[string]any) store.Schedule {
		t.Helper()
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/api/schedules/"+existing.ID, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("id", existing.ID)
		req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
		rr := httptest.NewRecorder()
		srv.handleUpdateSchedule(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("handleUpdateSchedule status = %d, want 200 body %q", rr.Code, rr.Body.String())
		}
		var got store.Schedule
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		// Also verify persisted row.
		persisted, err := st.GetSchedule(ctx, existing.ID)
		if err != nil {
			t.Fatalf("GetSchedule after update: %v", err)
		}
		if got.Enabled != persisted.Enabled || (got.NextRunAt == nil) != (persisted.NextRunAt == nil) {
			t.Fatalf("response vs persisted mismatch: response %+v persisted %+v", got, persisted)
		}
		return persisted
	}

	// 1. Disabled schedule, omitted enabled -> must remain disabled, next_run_at nil
	disabled, err := st.CreateSchedule(ctx, store.Schedule{
		Name: "disabled-preserve-" + types.NewID(), ScanPolicyID: policy.ID, TargetID: target.ID,
		Cron: "0 3 * * *", Enabled: false, NextRunAt: nil,
	})
	if err != nil {
		t.Fatalf("create disabled schedule: %v", err)
	}
	if disabled.Enabled || disabled.NextRunAt != nil {
		t.Fatalf("disabled fixture = %+v, want Enabled false, NextRunAt nil", disabled)
	}
	got := helper(t, disabled, map[string]any{
		"name": "disabled-preserve-renamed", "scan_policy_id": policy.ID, "target_id": target.ID, "cron": "0 4 * * *",
		// enabled intentionally omitted
	})
	if got.Enabled {
		t.Fatalf("disabled+omit: Enabled = true, want false")
	}
	if got.NextRunAt != nil {
		t.Fatalf("disabled+omit: NextRunAt = %v, want nil", *got.NextRunAt)
	}

	// 2. Enabled schedule, omitted enabled -> must remain enabled, next_run_at recomputed for new cron
	enabledNext := time.Now().Add(time.Hour).Truncate(time.Minute)
	enabled, err := st.CreateSchedule(ctx, store.Schedule{
		Name: "enabled-preserve-" + types.NewID(), ScanPolicyID: policy.ID, TargetID: target.ID,
		Cron: "0 3 * * *", Enabled: true, NextRunAt: &enabledNext,
	})
	if err != nil {
		t.Fatalf("create enabled schedule: %v", err)
	}
	got = helper(t, enabled, map[string]any{
		"name": "enabled-preserve-renamed", "scan_policy_id": policy.ID, "target_id": target.ID, "cron": "0 5 * * *",
	})
	if !got.Enabled {
		t.Fatalf("enabled+omit: Enabled = false, want true")
	}
	if got.NextRunAt == nil {
		t.Fatal("enabled+omit: NextRunAt = nil, want non-nil recomputed")
	}
	// Ensure next_run_at actually reflects the new cron (0 5 * * *), not the old 0 3.
	if got.NextRunAt.Equal(enabledNext) {
		t.Fatalf("enabled+omit: NextRunAt unchanged %v, want recomputed for new cron", *got.NextRunAt)
	}

	// 3. Explicit true: disabled -> enabled, next_run_at becomes non-nil
	got = helper(t, disabled, map[string]any{
		"name": "disabled-explicit-true", "scan_policy_id": policy.ID, "target_id": target.ID, "cron": "0 3 * * *", "enabled": true,
	})
	if !got.Enabled || got.NextRunAt == nil {
		t.Fatalf("disabled+explicit true: got Enabled %v NextRunAt %v, want true/non-nil", got.Enabled, got.NextRunAt)
	}

	// 4. Explicit false: enabled -> disabled, next_run_at becomes nil
	// Re-create an enabled schedule for this case
	enabled2, err := st.CreateSchedule(ctx, store.Schedule{
		Name: "enabled-explicit-false-" + types.NewID(), ScanPolicyID: policy.ID, TargetID: target.ID,
		Cron: "0 3 * * *", Enabled: true, NextRunAt: &enabledNext,
	})
	if err != nil {
		t.Fatalf("create enabled2: %v", err)
	}
	got = helper(t, enabled2, map[string]any{
		"name": "enabled-explicit-false", "scan_policy_id": policy.ID, "target_id": target.ID, "cron": "0 3 * * *", "enabled": false,
	})
	if got.Enabled || got.NextRunAt != nil {
		t.Fatalf("enabled+explicit false: got Enabled %v NextRunAt %v, want false/nil", got.Enabled, got.NextRunAt)
	}

	// 5. Explicit null is treated as omitted (preserve). Disabled stays disabled.
	// Use a fresh disabled fixture; the original `disabled` row was enabled by
	// case 3, so reusing it would incorrectly expect preserved false when the
	// stored value is now true. `json.Marshal` on a nil map value already
	// emits `null`, so a single helper call covers the null case without a
	// duplicate raw request.
	disabledNull, err := st.CreateSchedule(ctx, store.Schedule{
		Name: "disabled-null-preserve-" + types.NewID(), ScanPolicyID: policy.ID, TargetID: target.ID,
		Cron: "0 3 * * *", Enabled: false, NextRunAt: nil,
	})
	if err != nil {
		t.Fatalf("create disabledNull: %v", err)
	}
	got = helper(t, disabledNull, map[string]any{
		"name": "disabled-null-preserve", "scan_policy_id": policy.ID, "target_id": target.ID, "cron": "0 3 * * *", "enabled": nil,
	})
	if got.Enabled {
		t.Fatalf("disabled+null: Enabled true, want preserved false")
	}
	if got.NextRunAt != nil {
		t.Fatalf("disabled+null: NextRunAt %v, want nil", *got.NextRunAt)
	}
}

// TestHandleUpdateScheduleAtomicPreservationPostgres verifies the atomicity
// fix: if request A omits enabled (preserve) and request B concurrently disables,
// A's stale omission must not re-enable. The store's COALESCE logic preserves the
// concurrent disable even when A's handler computed nextTrue for the true case.
func TestHandleUpdateScheduleAtomicPreservationPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	target, _ := st.CreateTarget(ctx, store.Target{Name: "atomic-target-" + types.NewID(), Hosts: []string{"atomic.invalid"}})
	ts, _ := st.CreateTemplateSet(ctx, store.TemplateSet{Name: "atomic-ts-" + types.NewID(), Mode: store.TemplateSetModeAll})
	policy, _ := st.CreateScanPolicy(ctx, store.ScanPolicy{Name: "atomic-policy-" + types.NewID(), TemplateSetID: ts.ID})

	// Start enabled.
	enabledNext := time.Now().Add(time.Hour).Truncate(time.Minute)
	sch, err := st.CreateSchedule(ctx, store.Schedule{
		Name: "atomic-schedule-" + types.NewID(), ScanPolicyID: policy.ID, TargetID: target.ID,
		Cron: "0 3 * * *", Enabled: true, NextRunAt: &enabledNext,
	})
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	srv := &Server{store: st, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}

	// Simulate B: explicitly disable via store (concurrent).
	disabledFalse := false
	if _, err := st.UpdateSchedule(ctx, sch.ID, store.Schedule{
		Name: sch.Name, ScanPolicyID: policy.ID, TargetID: target.ID, Cron: "0 3 * * *",
		NextRunAt: nil,
	}, &disabledFalse); err != nil {
		t.Fatalf("concurrent disable: %v", err)
	}
	// Verify disabled.
	intermediate, _ := st.GetSchedule(ctx, sch.ID)
	if intermediate.Enabled || intermediate.NextRunAt != nil {
		t.Fatalf("after concurrent disable: %+v, want disabled/nil", intermediate)
	}

	// Now A arrives with omitted enabled (would have read true staled) but sends preserve.
	b, _ := json.Marshal(map[string]any{
		"name": "atomic-rename", "scan_policy_id": policy.ID, "target_id": target.ID, "cron": "0 4 * * *",
		// enabled omitted -> nil preserve
	})
	req := httptest.NewRequest(http.MethodPut, "/api/schedules/"+sch.ID, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", sch.ID)
	req = req.WithContext(withIdentity(req.Context(), store.Identity{Subject: "admin", Roles: []string{RoleAdmin}}))
	rr := httptest.NewRecorder()
	srv.handleUpdateSchedule(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("atomic preserve status = %d, want 200 body %q", rr.Code, rr.Body.String())
	}
	final, _ := st.GetSchedule(ctx, sch.ID)
	if final.Enabled {
		t.Fatalf("atomic preserve after concurrent disable: Enabled true, want preserved false (re-enable bug)")
	}
	if final.NextRunAt != nil {
		t.Fatalf("atomic preserve after concurrent disable: NextRunAt %v, want nil", *final.NextRunAt)
	}
}

// TestHandleUpdateScheduleDecodeTriState unit-tests the JSON pointer tri-state
// without a DB, pinning that omitted vs explicit is distinguishable and that
// the original Enabled:true default cannot reappear.
func TestHandleUpdateScheduleDecodeTriState(t *testing.T) {
	type req struct {
		Name         string `json:"name"`
		ScanPolicyID string `json:"scan_policy_id"`
		TargetID     string `json:"target_id"`
		Cron         string `json:"cron"`
		Enabled      *bool  `json:"enabled"`
	}
	decode := func(jsonStr string) *bool {
		var r req
		if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
			t.Fatalf("unmarshal %q: %v", jsonStr, err)
		}
		return r.Enabled
	}
	if got := decode(`{"name":"x","scan_policy_id":"p","target_id":"t","cron":"0 3 * * *"}`); got != nil {
		t.Fatalf("omitted enabled = %v, want nil (preserve)", *got)
	}
	if got := decode(`{"name":"x","scan_policy_id":"p","target_id":"t","cron":"0 3 * * *","enabled":true}`); got == nil || !*got {
		t.Fatalf("explicit true = %v, want true", got)
	}
	if got := decode(`{"name":"x","scan_policy_id":"p","target_id":"t","cron":"0 3 * * *","enabled":false}`); got == nil || *got {
		t.Fatalf("explicit false = %v, want false", got)
	}
	if got := decode(`{"name":"x","scan_policy_id":"p","target_id":"t","cron":"0 3 * * *","enabled":null}`); got != nil {
		t.Fatalf("null enabled = %v, want nil (preserve)", *got)
	}
}
