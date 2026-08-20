package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// lastAudit parses the final JSON log line written to buf.
func lastAudit(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) == 0 || len(lines[len(lines)-1]) == 0 {
		t.Fatal("no log line emitted")
	}
	var ev map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	return ev
}

func TestStatusRecorder(t *testing.T) {
	// No explicit write: status stays at the 200 default.
	sr := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	if sr.status != http.StatusOK || sr.written {
		t.Fatalf("fresh recorder: status=%d written=%v", sr.status, sr.written)
	}
	// First WriteHeader wins; a later one is ignored (mirrors net/http).
	sr.WriteHeader(http.StatusNoContent)
	sr.WriteHeader(http.StatusInternalServerError)
	if sr.status != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (first WriteHeader wins)", sr.status)
	}

	// A bare Write implies 200.
	sr2 := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	if _, err := sr2.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if !sr2.written || sr2.status != http.StatusOK {
		t.Errorf("after Write: status=%d written=%v, want 200/true", sr2.status, sr2.written)
	}

	underlying := httptest.NewRecorder()
	sr3 := &statusRecorder{ResponseWriter: underlying, status: http.StatusOK}
	if got := sr3.Unwrap(); got != underlying {
		t.Fatalf("Unwrap returned %T, want the wrapped response writer", got)
	}
}

func TestRecordAuditFields(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{log: slog.New(slog.NewJSONHandler(&buf, nil))}

	req := httptest.NewRequest(http.MethodDelete, "/api/targets/t1", nil)
	req.SetPathValue("id", "t1")
	id := store.Identity{Subject: "alice", Email: "alice@example.com", Roles: []string{RoleAdmin}}

	s.recordAudit(req, id, eventConfigChanged, "target.delete", "target", http.StatusOK, 3*time.Millisecond)
	ev := lastAudit(t, &buf)

	want := map[string]any{
		"event":         "audit",
		"event_id":      eventConfigChanged,
		"action":        "target.delete",
		"actor_subject": "alice",
		"actor_email":   "alice@example.com",
		"object_type":   "target",
		"object_id":     "t1",
		"method":        http.MethodDelete,
		"path":          "/api/targets/t1",
	}
	for k, v := range want {
		if ev[k] != v {
			t.Errorf("field %q = %v, want %v", k, ev[k], v)
		}
	}
	if ev["status"] != float64(http.StatusOK) {
		t.Errorf("status = %v, want 200", ev["status"])
	}
	if _, ok := ev["duration_ms"]; !ok {
		t.Error("duration_ms missing")
	}

	// A denial overrides event_id to access_denied, whatever was attempted.
	buf.Reset()
	s.recordAudit(req, id, eventConfigChanged, "target.delete", "target", http.StatusForbidden, time.Millisecond)
	ev = lastAudit(t, &buf)
	if ev["event_id"] != eventAccessDenied {
		t.Errorf("denied event_id = %v, want %q", ev["event_id"], eventAccessDenied)
	}
	if ev["status"] != float64(http.StatusForbidden) {
		t.Errorf("status = %v, want 403", ev["status"])
	}
}

func TestRecordAuditOmitsEmptyOptionals(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{log: slog.New(slog.NewJSONHandler(&buf, nil))}

	// A create: no path id, and an actor without an email.
	req := httptest.NewRequest(http.MethodPost, "/api/targets", nil)
	id := store.Identity{Subject: "svc", Roles: []string{RoleOperator}}
	s.recordAudit(req, id, eventConfigChanged, "target.create", "target", http.StatusAccepted, time.Millisecond)

	ev := lastAudit(t, &buf)
	if _, ok := ev["object_id"]; ok {
		t.Error("object_id should be omitted when the path has no id")
	}
	if _, ok := ev["actor_email"]; ok {
		t.Error("actor_email should be omitted when the identity has none")
	}
	if ev["actor_subject"] != "svc" {
		t.Errorf("actor_subject = %v, want svc", ev["actor_subject"])
	}
}

func TestMutationEmitsAndCallsNext(t *testing.T) {
	var buf bytes.Buffer
	// auth == nil ⇒ requireAuth injects devIdentity (all roles), so the call is
	// authorized and reaches next.
	s := &Server{log: slog.New(slog.NewJSONHandler(&buf, nil))}

	called := false
	h := s.mutation(eventConfigChanged, "target.create", "target", RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		called = true
		addAuditFields(r, slog.String("target_id", "t1"), slog.String("scan_policy_id", "p1"))
		w.WriteHeader(http.StatusCreated)
	})

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/api/targets", nil))

	if !called {
		t.Fatal("next handler was not called")
	}
	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rr.Code)
	}
	ev := lastAudit(t, &buf)
	if ev["event"] != "audit" || ev["event_id"] != eventConfigChanged || ev["action"] != "target.create" {
		t.Errorf("unexpected audit event: %v", ev)
	}
	if ev["status"] != float64(http.StatusCreated) {
		t.Errorf("audit status = %v, want 201", ev["status"])
	}
	if ev["actor_subject"] != "dev" {
		t.Errorf("actor_subject = %v, want dev (devIdentity)", ev["actor_subject"])
	}
	if ev["target_id"] != "t1" || ev["scan_policy_id"] != "p1" {
		t.Errorf("handler audit fields missing: %v", ev)
	}
}

func TestLogSystemAuditIncludesResolvedContext(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	logSystemAudit(context.Background(), log, eventScanDispatched, "schedule.run", "scan", "scan1",
		slog.String("scan_policy_id", "policy1"),
		slog.String("target_id", "target1"),
		slog.String("scan_id", "scan1"),
	)
	ev := lastAudit(t, &buf)

	want := map[string]any{
		"event":          "audit",
		"event_id":       eventScanDispatched,
		"action":         "schedule.run",
		"actor_subject":  "system",
		"actor_type":     "system",
		"object_type":    "scan",
		"object_id":      "scan1",
		"scan_policy_id": "policy1",
		"target_id":      "target1",
		"scan_id":        "scan1",
	}
	for key, value := range want {
		if ev[key] != value {
			t.Errorf("field %q = %v, want %v", key, ev[key], value)
		}
	}
}
