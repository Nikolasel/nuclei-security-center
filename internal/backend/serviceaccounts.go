package backend

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Service-account API tokens (#70). An additive, NSC-local credential for
// unattended automation (cron/CI pulling GET /api/findings/export into
// DefectDojo, etc.): scoped to one role, revocable independently of any human's
// IdP session, individually auditable, and long-lived-but-expiring. It does NOT
// replace the OIDC/BFF session cookie — that stays the only path for interactive
// users. Managing these credentials is admin-only.

const (
	// tokenScheme is the fixed prefix on every minted token, so a stray
	// Authorization header for some other scheme is easy to reject and a leaked
	// token is greppable/recognizable in logs and secret scanners.
	tokenScheme = "nsc_"
	// tokenPrefixLen is how many leading characters of the token are stored in
	// cleartext (token_prefix) purely so an operator can match a listed row to
	// the token string they saved. Well short of guessable entropy.
	tokenPrefixLen = 12
	// defaultTokenTTLDays applies when a create/rotate request omits ttl_days.
	// Long enough for cron/CI, but not indefinite (the issue's "expiry" ask).
	defaultTokenTTLDays = 90
)

// mintToken returns a new opaque token and its storage hash + display prefix.
// The token carries 256 bits of CSPRNG entropy, so a fast hash (SHA-256) with an
// exact-hash lookup is the correct primitive — no password KDF, which is for
// low-entropy human secrets (invariant #5: use the library, don't over-build).
func mintToken() (token, hash, prefix string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", err
	}
	token = tokenScheme + base64.RawURLEncoding.EncodeToString(buf)
	return token, hashToken(token), token[:tokenPrefixLen], nil
}

// hashToken is the at-rest representation of a token: hex-encoded SHA-256.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// bearerToken extracts an NSC service-account token from the Authorization
// header. ok is false when there's no bearer token to consider, so the caller
// falls through to the session-cookie path.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	return h[len(p):], true
}

// resolveServiceToken authenticates a bearer token to an identity, or returns an
// error if it's malformed, unknown, revoked, or expired. On success it records a
// best-effort last-used timestamp (never failing the request if that write does).
func (s *Server) resolveServiceToken(ctx context.Context, token string) (store.Identity, error) {
	if !strings.HasPrefix(token, tokenScheme) {
		return store.Identity{}, errors.New("not a service-account token")
	}
	id, acctID, err := s.store.AuthenticateServiceAccount(ctx, hashToken(token))
	if err != nil {
		return store.Identity{}, err
	}
	// Detach from the request context so a client disconnect can't abort the
	// touch mid-write; keep it bounded.
	go func() {
		tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.TouchServiceAccount(tctx, acctID); err != nil && s.log != nil {
			s.log.Warn("touch service account", "err", err)
		}
	}()
	return id, nil
}

// --- admin CRUD ---

type createServiceAccountReq struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	TTLDays *int   `json:"ttl_days,omitempty"` // nil => default; 0 => no expiry
}

// serviceAccountWithToken is the create/rotate response: the account plus the
// plaintext token, which is returned exactly once and never stored or shown again.
type serviceAccountWithToken struct {
	store.ServiceAccount
	Token string `json:"token"`
}

func (s *Server) handleListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	accts, err := s.store.ListServiceAccounts(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accts)
}

func (s *Server) handleCreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	var req createServiceAccountReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if !isAssignableRole(req.Role) {
		http.Error(w, "role must be one of viewer, operator, admin", http.StatusBadRequest)
		return
	}
	expiresAt, err := expiryFromTTL(req.TTLDays)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, hash, prefix, err := mintToken()
	if err != nil {
		s.serverError(w, "mint token", err)
		return
	}
	sa, err := s.store.CreateServiceAccount(r.Context(), store.ServiceAccount{
		Name:        req.Name,
		Role:        req.Role,
		TokenPrefix: prefix,
		CreatedBy:   identityFrom(r.Context()).Subject,
	}, hash, expiresAt)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, serviceAccountWithToken{ServiceAccount: sa, Token: token})
}

func (s *Server) handleRotateServiceAccount(w http.ResponseWriter, r *http.Request) {
	// ttl_days is optional on rotate; omitted keeps the default lifetime.
	var req createServiceAccountReq
	if r.ContentLength != 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}
	expiresAt, err := expiryFromTTL(req.TTLDays)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, hash, prefix, err := mintToken()
	if err != nil {
		s.serverError(w, "mint token", err)
		return
	}
	sa, err := s.store.RotateServiceAccountToken(r.Context(), r.PathValue("id"), hash, prefix, expiresAt)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, serviceAccountWithToken{ServiceAccount: sa, Token: token})
}

func (s *Server) handleDeleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteServiceAccount(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// isAssignableRole reports whether role is one a token may be minted with — the
// same three RBAC roles the session cookie uses.
func isAssignableRole(role string) bool {
	switch role {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	default:
		return false
	}
}

// expiryFromTTL maps the request's ttl_days to an absolute expiry: nil ttl uses
// the default lifetime, an explicit 0 means no expiry, and a positive value sets
// that many days out. Negative is rejected.
func expiryFromTTL(ttlDays *int) (*time.Time, error) {
	days := defaultTokenTTLDays
	if ttlDays != nil {
		days = *ttlDays
	}
	switch {
	case days < 0:
		return nil, errors.New("ttl_days must be zero (no expiry) or a positive number of days")
	case days == 0:
		return nil, nil
	default:
		t := time.Now().Add(time.Duration(days) * 24 * time.Hour)
		return &t, nil
	}
}
