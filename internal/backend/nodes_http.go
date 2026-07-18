package backend

import (
	"net"
	"net/http"
	"strings"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Scanner node admin endpoints (#22). The registry is DB-backed and managed by
// the admin (or a service-account script) — nodes never call the backend. Reads
// need viewer; create/update/delete need admin and are audited as config changes.
//
// The node token is write-only: it's accepted on create/update but never
// serialized back (blanked on every read path), the same posture as a
// service-account token.

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListScannerNodes(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	for i := range nodes {
		nodes[i].Token = ""
	}
	if nodes == nil {
		nodes = []store.ScannerNode{}
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	node, err := s.store.GetScannerNode(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	node.Token = ""
	writeJSON(w, http.StatusOK, node)
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
	node.Token = ""
	writeJSON(w, http.StatusCreated, node)
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	var in store.ScannerNode
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validateNode(&in, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	node, err := s.store.UpdateScannerNode(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	node.Token = ""
	writeJSON(w, http.StatusOK, node)
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
