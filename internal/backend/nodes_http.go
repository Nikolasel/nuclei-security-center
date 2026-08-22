package backend

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
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

// scannerNodeInput keeps max_concurrent_scans as a pointer so an update from an
// older client that omits the field preserves the stored capacity. An explicit
// zero remains distinguishable and is rejected by validateNode.
type scannerNodeInput struct {
	Name               string   `json:"name"`
	Endpoint           string   `json:"endpoint"`
	Token              string   `json:"token"`
	CIDRs              []string `json:"cidrs"`
	Tags               []string `json:"tags"`
	MaxConcurrentScans *int     `json:"max_concurrent_scans"`
	TLSServerCA        string   `json:"tls_server_ca"`
	TLSClientCert      string   `json:"tls_client_cert"`
	TLSClientKey       string   `json:"tls_client_key"`
}

func (in scannerNodeInput) storeNode(defaultMaxConcurrentScans int) store.ScannerNode {
	maxConcurrentScans := defaultMaxConcurrentScans
	if in.MaxConcurrentScans != nil {
		maxConcurrentScans = *in.MaxConcurrentScans
	}
	return store.ScannerNode{
		Name:               in.Name,
		Endpoint:           in.Endpoint,
		Token:              in.Token,
		CIDRs:              in.CIDRs,
		Tags:               in.Tags,
		MaxConcurrentScans: maxConcurrentScans,
		TLSServerCA:        in.TLSServerCA,
		TLSClientCert:      in.TLSClientCert,
		TLSClientKey:       in.TLSClientKey,
	}
}

// effectiveNodeForUpdate resolves the effective ScannerNode that will be
// persisted and validated for a PUT /api/nodes/{id}. It merges keep-on-blank
// fields (max_concurrent_scans, tls_client_key) with the existing row and
// normalizes TLS material so the caller can validate and persist the same
// object. Extracted for testability — tests should call this helper instead
// of copying the resolution logic (#198).
func effectiveNodeForUpdate(existing store.ScannerNode, payload scannerNodeInput, defaultMaxConcurrentScans int) store.ScannerNode {
	in := payload.storeNode(defaultMaxConcurrentScans)
	if payload.MaxConcurrentScans == nil {
		in.MaxConcurrentScans = existing.MaxConcurrentScans
	}
	// Resolve effective TLS material: tls_server_ca and tls_client_cert are
	// cleared when blank, while tls_client_key is paired with the cert.
	// A blank cert means no client cert is configured, so the paired key must
	// be cleared as well — this is what lets an mTLS node transition to plain
	// http:// (UI sends blank CA/cert + omitted key, see NodesPage.tsx) without
	// leaving an orphaned key that would make the new http+key invalid (#198).
	rawCA := strings.TrimSpace(payload.TLSServerCA)
	rawCert := strings.TrimSpace(payload.TLSClientCert)
	rawKey := strings.TrimSpace(payload.TLSClientKey)
	in.TLSServerCA = rawCA
	in.TLSClientCert = rawCert
	if rawCert == "" {
		in.TLSClientKey = ""
	} else if rawKey != "" {
		in.TLSClientKey = rawKey
	} else {
		in.TLSClientKey = existing.TLSClientKey
	}
	return in
}

// nodeView builds the API view of a node, merging in its health record. The
// bearer token and the mTLS client key are always blanked (write-only secrets);
// the server CA and client cert are public and returned as-is.
func (s *Server) nodeView(n store.ScannerNode) nodeView {
	n.Token = ""
	n.TLSClientKey = ""
	v := nodeView{ScannerNode: n}
	if s.orch != nil {
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
	var payload scannerNodeInput
	if !decodeJSON(w, r, &payload) {
		return
	}
	in := payload.storeNode(types.DefaultMaxConcurrentScans)
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
	var payload scannerNodeInput
	if !decodeJSON(w, r, &payload) {
		return
	}
	// Update needs the existing row to resolve keep-on-blank fields and to
	// compute the effective TLS state that will be persisted and validated.
	existing, err := s.store.GetScannerNode(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	in := effectiveNodeForUpdate(existing, payload, types.DefaultMaxConcurrentScans)
	// Token optional on update: a blank one keeps the stored value (it's
	// write-only, so the admin can't re-supply it when editing other fields).
	// store.UpdateScannerNode keeps it via COALESCE, so leave in.Token as-is
	// (blank) for that path; validation allows it when requireToken is false.
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
	if err := validateNodeEndpoint(in.Endpoint); err != nil {
		return err
	}
	if requireToken && strings.TrimSpace(in.Token) == "" {
		return errBadRequest("token is required")
	}
	if in.MaxConcurrentScans < 1 || in.MaxConcurrentScans > types.MaxConcurrentScansCeiling {
		return errBadRequest(fmt.Sprintf("max_concurrent_scans must be between 1 and %d", types.MaxConcurrentScansCeiling))
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

func validateNodeEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errBadRequest("endpoint must be an absolute http or https URL")
	}
	if u.User != nil {
		return errBadRequest("endpoint must not contain credentials")
	}
	if u.Fragment != "" {
		return errBadRequest("endpoint must not contain a fragment")
	}
	if strings.Contains(endpoint, " ") || strings.Contains(endpoint, "\n") || strings.Contains(endpoint, "\r") || strings.Contains(endpoint, "\t") {
		return errBadRequest("endpoint must not contain whitespace")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return errBadRequest("endpoint must not target localhost")
	}
	// Literal-IP checks are DNS-free (consistent with target validation):
	// a hostname that resolves to loopback/link-local bypasses this, which is
	// acceptable for an admin-only, defense-in-depth check. Private networks
	// (10/8, 172.16/12, 192.168/16, fc00::/7) remain allowed because scanner
	// nodes commonly live there; the most sensitive link-local target
	// (169.254.169.254, fe80::) is blocked.
	hostWithoutZone := strings.Split(host, "%")[0] // strip IPv6 zone e.g. fe80::1%eth0
	if ip := net.ParseIP(hostWithoutZone); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return errBadRequest("endpoint must not target a loopback or link-local address")
		}
	}
	return nil
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

	// Per-node mTLS is only meaningful over TLS — Go's http.Transport ignores
	// TLSClientConfig for plain http:// requests, so accepting the material
	// would silently leave the bearer token and results in cleartext on the
	// segment the feature exists to protect (#198).
	if u, err := url.Parse(strings.TrimSpace(in.Endpoint)); err == nil && u.Scheme == "http" {
		if in.TLSServerCA != "" || in.TLSClientCert != "" || in.TLSClientKey != "" {
			return errBadRequest("TLS configuration requires an https endpoint")
		}
	}

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
