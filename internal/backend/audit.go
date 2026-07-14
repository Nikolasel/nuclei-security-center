package backend

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Audit log (Phase 3). Every mutating API call emits one structured log event
// (event=audit) to stdout — who did what, to which object, with what result.
// The audit trail deliberately lives in the platform's log aggregator
// (CloudWatch / Azure Log Analytics / GCP Cloud Logging / Loki), not in the app
// database: the aggregator already solves retention, indexing, tamper-evidence,
// and querying, and keeping the trail off the app DB means a DB compromise can't
// rewrite it. This matches §6's "SIEM shipping of the audit log" and the app's
// existing slog-JSON-to-stdout convention. Filter on `event="audit"` to isolate.

// Audit event_id vocabulary — a small, stable, low-cardinality set that SIEM
// detections and dashboards key off (vs. the finer-grained `action` attribute,
// which is for forensics). A denied attempt is always access_denied regardless
// of what it tried to do; a successful mutation gets its semantic category.
const (
	eventAccessDenied          = "access_denied"           // authz rejected the call (403)
	eventConfigChanged         = "config_changed"          // targets / template sets / schedules CUD
	eventScanDispatched        = "scan_dispatched"         // ad-hoc scan submit or schedule run
	eventFindingTriaged        = "finding_triaged"         // disposition / severity recast
	eventServiceAccountChanged = "service_account_changed" // service-account token create/rotate/revoke
)

// statusRecorder wraps a ResponseWriter to remember the status code the handler
// emitted, so the audit event can record the outcome. A handler that writes a
// body without an explicit WriteHeader implies 200 (net/http's own default).
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.written {
		r.status = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.status = http.StatusOK
		r.written = true
	}
	return r.ResponseWriter.Write(b)
}

// mutation guards a mutating handler with authz and emits an audit event for the
// attempt — including authz denials, which are the security-interesting case.
// eventID is the success-path category (e.g. config_changed); a denial overrides
// it to access_denied. action names the operation ("target.create"); objectType
// names the resource kind ("target"). It replaces requireRole on mutating routes.
func (s *Server) mutation(eventID, action, objectType, role string, next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		id := identityFrom(r.Context())
		if !satisfies(id, role) {
			http.Error(rec, "insufficient role", http.StatusForbidden)
		} else {
			next(rec, r)
		}
		s.recordAudit(r, id, eventID, action, objectType, rec.status, time.Since(start))
	})
}

// recordAudit emits the structured audit event, always at INFO — a mutation and
// an authz denial are both the system working as designed, not a malfunction, so
// neither warrants WARN (that's reserved for things that are actually broken).
// Alerting on denials keys off the event_id/status fields in the aggregator.
// object_id is taken from the path where present (edits/deletes); creates carry
// none (the new id isn't in the request path — it's in the response body).
func (s *Server) recordAudit(r *http.Request, id store.Identity, eventID, action, objectType string, status int, dur time.Duration) {
	if s.log == nil {
		return
	}
	if status == http.StatusForbidden {
		eventID = eventAccessDenied
	}
	attrs := []slog.Attr{
		slog.String("event", "audit"),
		slog.String("event_id", eventID),
		slog.String("action", action),
		slog.String("actor_subject", firstNonEmpty(id.Subject, "unknown")),
		slog.String("actor_type", actorType(id)),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.Int64("duration_ms", dur.Milliseconds()),
	}
	if id.Email != "" {
		attrs = append(attrs, slog.String("actor_email", id.Email))
	}
	if objectType != "" {
		attrs = append(attrs, slog.String("object_type", objectType))
	}
	if oid := r.PathValue("id"); oid != "" {
		attrs = append(attrs, slog.String("object_id", oid))
	}

	s.log.LogAttrs(r.Context(), slog.LevelInfo, "audit "+action, attrs...)
}

// actorType classifies the caller for audit detections: a service-account token
// (headless automation) vs. an interactive user. Service-account subjects carry
// the "svc:" prefix minted in store.AuthenticateServiceAccount.
func actorType(id store.Identity) string {
	if strings.HasPrefix(id.Subject, "svc:") {
		return "service_account"
	}
	return "user"
}
