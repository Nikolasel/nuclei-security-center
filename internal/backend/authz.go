package backend

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// The three roles, ordered by privilege. Roles are assigned by the IdP (a
// groups/roles claim), never in-app; see the auth slice in the architecture doc.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// roleRank ranks roles so a higher role satisfies a lower requirement (admin
// can do anything an operator can, etc.). Unknown roles rank 0.
var roleRank = map[string]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
}

// satisfies reports whether any of the identity's roles meets the required role.
func satisfies(id store.Identity, required string) bool {
	need := roleRank[required]
	for _, r := range id.Roles {
		if roleRank[r] >= need {
			return true
		}
	}
	return false
}

type ctxKey int

const identityKey ctxKey = 0

func withIdentity(ctx context.Context, id store.Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// identityFrom returns the caller's identity, or the zero value if unauthenticated.
func identityFrom(ctx context.Context) store.Identity {
	id, _ := ctx.Value(identityKey).(store.Identity)
	return id
}

// devIdentity is injected when auth is disabled (OIDC not configured) so
// handlers behave uniformly. It holds every role.
var devIdentity = store.Identity{Subject: "dev", Roles: []string{RoleAdmin, RoleOperator, RoleViewer}}

// requireAuth resolves the caller to an identity and injects it into the request
// context, or returns 401. With auth disabled it injects devIdentity. With auth
// enabled a caller authenticates either with a service-account bearer token
// (headless automation, #70) or the OIDC/BFF session cookie (interactive
// users) — the bearer token is tried first when present, and a bad token is
// rejected rather than silently falling through to the cookie.
//
// An infrastructure failure on the underlying store call (Postgres down,
// credential rotation, network partition) is not a 401 — it's a 503. The
// status reflects the real fault so the SPA doesn't bounce the user through
// login on every request (#82).
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuthWithResolvers(s.resolveServiceToken, func(r *http.Request) (store.Identity, error) {
		return s.auth.identityFromRequest(r)
	}, next)
}

// requireAuthWithResolvers keeps both credential lookups injectable for
// deterministic middleware tests. Production passes the real service-token and
// session resolvers; the auth-disabled branch returns before either is called.
func (s *Server) requireAuthWithResolvers(
	resolveBearer func(context.Context, string) (store.Identity, error),
	resolveSession func(*http.Request) (store.Identity, error),
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if s.auth == nil {
			next(w, r.WithContext(withIdentity(r.Context(), devIdentity)))
			return
		}
		if tok, ok := bearerToken(r); ok {
			id, err := resolveBearer(r.Context(), tok)
			if err != nil {
				if isAuthBackendFault(err) {
					s.serviceUnavailable(w, "authenticate service token", err)
					return
				}
				s.recordAuthenticationFailure(r, "bearer", start)
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}
			next(w, r.WithContext(withIdentity(r.Context(), id)))
			return
		}
		id, err := resolveSession(r)
		if err != nil {
			s.serviceUnavailable(w, "get session", err)
			return
		}
		if id.Subject == "" {
			authMethod := "none"
			if c, cookieErr := r.Cookie(s.auth.cfg.CookieName); cookieErr == nil && c.Value != "" {
				authMethod = "session"
			}
			s.recordAuthenticationFailure(r, authMethod, start)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(withIdentity(r.Context(), id)))
	}
}

// isAuthBackendFault reports whether err is an infrastructure failure on a
// session/lookup call rather than a credential failure. A credential failure
// (malformed token, unknown/revoked/expired session) is 401; a backend fault
// is 503.
func isAuthBackendFault(err error) bool {
	return err != nil && !errors.Is(err, store.ErrNotFound)
}

// serviceUnavailable logs the underlying fault and writes a generic 503 with a
// short Retry-After so the SPA and load balancers can back off and retry
// rather than treat the failure as "session expired" (#82).
func (s *Server) serviceUnavailable(w http.ResponseWriter, op string, err error) {
	if s.log != nil {
		s.log.Error(op, "err", err)
	}
	w.Header().Set("Retry-After", "5")
	http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
}

// requireRole wraps a handler so only callers holding at least `role` reach it.
// It implies requireAuth.
func (s *Server) requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !satisfies(identityFrom(r.Context()), role) {
			http.Error(w, "insufficient role", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
