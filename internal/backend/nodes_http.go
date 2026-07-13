package backend

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Scanner node registry endpoints (#22).
//
// POST /api/nodes/register is the one node→backend call in the system — a
// scanner node self-registering/heartbeating its metadata. It is NOT behind the
// session cookie / RBAC: a node has no user identity. It authenticates with the
// shared scanner bearer token (the same secret the backend uses to reach nodes),
// so only a node that already holds the token can register an endpoint.
//
// GET /api/nodes lists the registry for operators (session cookie, viewer role).

func (s *Server) handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	reg := s.orch.Registry()
	if reg == nil {
		http.Error(w, "node registry is not enabled", http.StatusNotFound)
		return
	}
	if !s.nodeTokenValid(r) {
		http.Error(w, "invalid scanner token", http.StatusUnauthorized)
		return
	}
	var body types.NodeRegistration
	if !decodeJSON(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Endpoint = strings.TrimSpace(body.Endpoint)
	if body.Endpoint == "" {
		http.Error(w, "endpoint is required", http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		body.Name = body.Endpoint
	}
	reg.Register(body)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	reg := s.orch.Registry()
	if reg == nil {
		writeJSON(w, http.StatusOK, []Node{})
		return
	}
	nodes := reg.List()
	if nodes == nil {
		nodes = []Node{}
	}
	writeJSON(w, http.StatusOK, nodes)
}

// nodeTokenValid checks the node-registration bearer token against the shared
// scanner token in constant time.
func (s *Server) nodeTokenValid(r *http.Request) bool {
	tok, ok := bearerAuth(r)
	if !ok || s.orch.nodeToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.orch.nodeToken)) == 1
}

// bearerAuth extracts a Bearer token from the Authorization header.
func bearerAuth(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	return h[len(p):], true
}
