package backend

import (
	"crypto/tls"
	"errors"
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
// bearer token and the mTLS client key are always blanked (write-only secrets);
// the server CA and client cert are public and returned as-is.
func (s *Server) nodeView(n store.ScannerNode) nodeView {
	n.Token = ""
	n.TLSClientKey = ""
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
	return validateNodeTLS(in, requireToken)
}

// validateNodeTLS checks a node's optional mTLS material so bad PEM is a clean
// 400 rather than a dispatch/health-poll failure later. The server CA (if given)
// must parse; the client cert + key must form a valid pair when both are present.
// On create (isCreate), a client cert and key must be supplied together — you
// can't have half a keypair. On update the key may be blank (keep the stored
// one), so a cert-only payload is allowed there and paired against the stored key
// at use time.
func validateNodeTLS(in *store.ScannerNode, isCreate bool) error {
	in.TLSServerCA = strings.TrimSpace(in.TLSServerCA)
	in.TLSClientCert = strings.TrimSpace(in.TLSClientCert)
	in.TLSClientKey = strings.TrimSpace(in.TLSClientKey)

	if in.TLSServerCA != "" {
		if _, err := certPoolFromPEM(in.TLSServerCA); err != nil {
			return errBadRequest("invalid server CA PEM")
		}
	}
	if isCreate {
		if (in.TLSClientCert == "") != (in.TLSClientKey == "") {
			return errBadRequest("client cert and key must be provided together")
		}
	}
	if in.TLSClientCert != "" && in.TLSClientKey != "" {
		if _, err := tls.X509KeyPair([]byte(in.TLSClientCert), []byte(in.TLSClientKey)); err != nil {
			return errBadRequest("client cert and key are not a valid pair")
		}
	}
	return nil
}

// handleSyncNodeTemplates pushes the current full catalog to one node on demand
// (#85, admin "sync now"). Full replace. 503 when distribution is disabled
// (no template sync configured), 404 for an unknown node, 502 when the node
// rejects or is unreachable.
func (s *Server) handleSyncNodeTemplates(w http.ResponseWriter, r *http.Request) {
	if s.distributor == nil {
		http.Error(w, "template distribution is disabled", http.StatusServiceUnavailable)
		return
	}
	status, err := s.distributor.SyncNode(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.log.Error("sync node templates", "node", r.PathValue("id"), "err", err)
		http.Error(w, "failed to sync templates to node: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// errBadRequest is a plain error whose text is safe to return to the client.
type errBadRequest string

func (e errBadRequest) Error() string { return string(e) }
