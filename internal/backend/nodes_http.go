package backend

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Scanner node admin endpoints (#22). The registry is DB-backed and managed by
// the admin (or a service-account script) — nodes never call the backend. Reads
// need viewer; create/update/delete need admin and are audited as config changes.
//
// The node token is write-only: it's accepted on create/update but never
// serialized back (blanked on every read path), the same posture as a
// service-account token.

// nodeView is a scanner node as returned by the API: the stored node (token
// blanked) plus derived liveness from the health monitor (#98). Healthy is a
// pointer so a not-yet-polled node reads as null ("unknown"), distinct from a
// node known to be down (false).
type nodeView struct {
	store.ScannerNode
	Healthy         *bool      `json:"healthy"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`
	NucleiVersion   string     `json:"nuclei_version,omitempty"`
	TemplatesCommit string     `json:"templates_commit,omitempty"`
	// HealthError is the last poll failure's message, set only while the node is
	// unhealthy — so an operator can tell a wrong token (401) from an unreachable
	// node without digging through backend logs.
	HealthError string `json:"health_error,omitempty"`
}

// nodeView builds the API view of a node, merging in its health record. The
// token is always blanked (write-only).
func (s *Server) nodeView(n store.ScannerNode) nodeView {
	n.Token = ""
	v := nodeView{ScannerNode: n}
	if h := s.orch.Health(); h != nil {
		if rec, known := h.Get(n.ID); known {
			healthy := rec.Healthy
			v.Healthy = &healthy
			if !rec.LastSeen.IsZero() {
				ls := rec.LastSeen
				v.LastSeen = &ls
			}
			v.NucleiVersion = rec.Capabilities.NucleiVersion
			v.TemplatesCommit = rec.Capabilities.TemplatesCommit
			if !rec.Healthy {
				v.HealthError = rec.LastError
			}
		}
	}
	return v
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListScannerNodes(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	views := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		views = append(views, s.nodeView(n))
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	node, err := s.store.GetScannerNode(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.nodeView(node))
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var in store.ScannerNode
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validateNode(&in, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.CreatedBy = identityFrom(r.Context()).Subject
	node, err := s.store.CreateScannerNode(r.Context(), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.nodeView(node))
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	var in store.ScannerNode
	if !decodeJSON(w, r, &in) {
		return
	}
	// Token optional on update: a blank one keeps the stored value (it's
	// write-only, so the admin can't re-supply it when editing other fields).
	if err := validateNode(&in, false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	node, err := s.store.UpdateScannerNode(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.nodeView(node))
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteScannerNode(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateNode checks a node payload before it reaches the store. requireToken is
// true for create/update (a node is unreachable without one). CIDRs are parsed
// here so a bad range is a clean 400, not a store error.
func validateNode(in *store.ScannerNode, requireToken bool) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Endpoint = strings.TrimSpace(in.Endpoint)
	if in.Name == "" {
		return errBadRequest("name is required")
	}
	if in.Endpoint == "" {
		return errBadRequest("endpoint is required")
	}
	if requireToken && strings.TrimSpace(in.Token) == "" {
		return errBadRequest("token is required")
	}
	for i, c := range in.CIDRs {
		c = strings.TrimSpace(c)
		if _, _, err := net.ParseCIDR(c); err != nil {
			return errBadRequest("invalid CIDR " + c)
		}
		in.CIDRs[i] = c
	}
	return nil
}

// errBadRequest is a plain error whose text is safe to return to the client.
type errBadRequest string

func (e errBadRequest) Error() string { return string(e) }
