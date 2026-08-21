package backend

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Audit log (Phase 3). Every mutating API call and rejected authentication emits
// one structured log event (event=audit) to stdout — who did what, to which
// object, with what result.
// The audit trail deliberately lives in the platform's log aggregator
// (CloudWatch / Azure Log Analytics / GCP Cloud Logging / Loki), not in the app
// database: the aggregator already solves retention, indexing, tamper-evidence,
// and querying, and keeping the trail off the app DB means a DB compromise can't
// rewrite it. The app's job ends at structured slog-JSON-to-stdout; whatever
// ships it onward (a sidecar forwarder, a SIEM connector, etc.) is a
// deployment concern, not an in-app feature. Filter on `event="audit"` to isolate.

// Audit event_id vocabulary — a small, stable, low-cardinality set that SIEM
// detections and dashboards key off (vs. the finer-grained `action` attribute,
// which is for forensics). A denied attempt is always access_denied regardless
// of what it tried to do; a successful mutation gets its semantic category.
const (
	eventAccessDenied          = "access_denied"           // authentication or audited authz rejected (401/403)
	eventConfigChanged         = "config_changed"          // config CUD and scan-history deletion
	eventScanDispatched        = "scan_dispatched"         // ad-hoc scan submit or schedule run
	eventFindingTriaged        = "finding_triaged"         // disposition / severity recast
	eventServiceAccountChanged = "service_account_changed" // service-account token create/rotate/revoke
	eventScanImported          = "scan_imported"           // scan bundle import recreated a scan + findings (#136)
	eventSessionRevoked        = "session_revoked"         // admin terminated a session or subject's sessions (#189)
)

// statusRecorder wraps a ResponseWriter to remember the status code the handler
// emitted, so the audit event can record the outcome. A handler that writes a
// body without an explicit WriteHeader implies 200 (net/http's own default).
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

// Unwrap lets http.ResponseController reach optional connection controls such
// as SetWriteDeadline through the audit wrapper.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// requestAuditFields is a request-scoped, handler-populated extension to the
// common audit envelope. The mutation middleware installs it before invoking a
// handler, and recordAudit reads it afterward. This lets a handler record
// resolved, non-secret identifiers that are not present in the URL without
// logging arbitrary request bodies.
type requestAuditFields struct {
	attrs []slog.Attr
}

type requestAuditFieldsKey struct{}

func addAuditFields(r *http.Request, attrs ...slog.Attr) {
	fields, _ := r.Context().Value(requestAuditFieldsKey{}).(*requestAuditFields)
	if fields != nil {
		fields.attrs = append(fields.attrs, attrs...)
	}
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
		r = r.WithContext(context.WithValue(r.Context(), requestAuditFieldsKey{}, &requestAuditFields{}))
		id := identityFrom(r.Context())
		if !s.mutationOriginAllowed(r) {
			http.Error(rec, "forbidden origin", http.StatusForbidden)
		} else if !satisfies(id, role) {
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
	if fields, _ := r.Context().Value(requestAuditFieldsKey{}).(*requestAuditFields); fields != nil {
		attrs = append(attrs, fields.attrs...)
	}

	s.log.LogAttrs(r.Context(), slog.LevelInfo, "audit "+action, attrs...)
}

// recordAuthenticationFailure emits the same low-cardinality denial event as a
// 403, but with an unknown actor: authentication did not establish an identity.
// authMethod is a non-secret classification (none, session, or bearer); token
// and cookie values are deliberately never included in the audit record.
func (s *Server) recordAuthenticationFailure(r *http.Request, authMethod string, start time.Time) {
	if s.log == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("event", "audit"),
		slog.String("event_id", eventAccessDenied),
		slog.String("action", "auth.authenticate"),
		slog.String("actor_subject", "unknown"),
		slog.String("actor_type", "unknown"),
		slog.String("auth_method", authMethod),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", http.StatusUnauthorized),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
	}
	s.log.LogAttrs(r.Context(), slog.LevelInfo, "audit auth.authenticate", attrs...)
}

// logSystemAudit emits an audit event for a mutation the system performs on its
// own — no HTTP request, no user (e.g. the retention sweeper deleting scans).
// recordAudit needs an *http.Request for the actor/method/path, which a
// background job doesn't have; this keeps the same event=audit contract with
// actor_type="system" so automated mutations are still visible in the aggregator
// (docs/ARCHITECTURE.md's guarantee that every mutation is logged). Additional
// attrs carry resolved, non-secret context such as a scheduled scan's policy and
// target. Always INFO, like recordAudit — a routine automated action isn't a fault.
func logSystemAudit(ctx context.Context, log *slog.Logger, eventID, action, objectType, objectID string, extra ...slog.Attr) {
	if log == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("event", "audit"),
		slog.String("event_id", eventID),
		slog.String("action", action),
		slog.String("actor_subject", "system"),
		slog.String("actor_type", "system"),
	}
	if objectType != "" {
		attrs = append(attrs, slog.String("object_type", objectType))
	}
	if objectID != "" {
		attrs = append(attrs, slog.String("object_id", objectID))
	}
	attrs = append(attrs, extra...)
	log.LogAttrs(ctx, slog.LevelInfo, "audit "+action, attrs...)
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
