package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// ErrScannerBusy marks an operation the node refused because a scan currently
// holds its active template tree. Pre-dispatch top-up waits and retries it.
var ErrScannerBusy = errors.New("scanner node busy")

// ScannerClient talks to one scanner node's /v1 API using a bearer service token.
// When tlsCfg is set (per-node mTLS, #26) it is applied to every request the
// client makes — including the long-lived results fetch — so a node in an
// untrusted segment is reached over a mutually-authenticated connection.
type ScannerClient struct {
	baseURL string
	token   string
	tlsCfg  *tls.Config
	http    *http.Client
	// httpForTimeout is a test seam for dedicated long/short-lived clients.
	// Production leaves it nil and uses newHTTPClient.
	httpForTimeout func(time.Duration) *http.Client
}

// maxScannerJSONResponseBytes caps every non-streaming response from a scanner
// node. Results and logs have separate streaming ceilings; control-plane JSON
// must be bounded before encoding/json can allocate from node-controlled input.
const (
	maxScannerJSONResponseBytes     = 16 << 20 // 16 MiB
	maxScannerStatusCollectionItems = 500_000  // 500k; the 16 MiB body cap remains authoritative
	maxScannerNodeStringBytes       = 64 << 10 // 64 KiB per node-supplied string
)

func decodeScannerJSON(body io.Reader, dst any) error {
	// Read one byte beyond the cap so a valid document followed by oversized
	// trailing data is rejected too. Decoding directly from a LimitedReader
	// would otherwise accept the first JSON value without consuming the body.
	b, err := io.ReadAll(io.LimitReader(body, maxScannerJSONResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read scanner response: %w", err)
	}
	if len(b) > maxScannerJSONResponseBytes {
		return scannerResponseTooLargeError()
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return ensureScannerJSONEOF(dec)
}

func scannerResponseTooLargeError() error {
	return fmt.Errorf("scanner response body exceeds %d-byte limit", maxScannerJSONResponseBytes)
}

func ensureScannerJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not supported")
		}
		return err
	}
	return nil
}

func decodeScannerStatus(body io.Reader, st *types.ScanStatus) error {
	limited := &io.LimitedReader{R: body, N: maxScannerJSONResponseBytes + 1}
	dec := json.NewDecoder(limited)
	if err := decodeScannerStatusObject(dec, st); err != nil {
		if limited.N <= 0 {
			return scannerResponseTooLargeError()
		}
		return err
	}
	if err := ensureScannerJSONEOF(dec); err != nil {
		if limited.N <= 0 {
			return scannerResponseTooLargeError()
		}
		return err
	}
	if limited.N <= 0 {
		return scannerResponseTooLargeError()
	}
	return nil
}

func decodeScannerStatusObject(dec *json.Decoder, st *types.ScanStatus) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("scanner status must be a JSON object")
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		field, ok := key.(string)
		if !ok {
			return errors.New("scanner status field name must be a string")
		}
		switch {
		case strings.EqualFold(field, "id"):
			err = dec.Decode(&st.ID)
		case strings.EqualFold(field, "state"):
			err = dec.Decode(&st.State)
		case strings.EqualFold(field, "nuclei_version"):
			err = dec.Decode(&st.NucleiVersion)
		case strings.EqualFold(field, "templates_commit"):
			err = dec.Decode(&st.TemplatesCommit)
		case strings.EqualFold(field, "finding_count"):
			err = dec.Decode(&st.FindingCount)
		case strings.EqualFold(field, "error"):
			err = dec.Decode(&st.Error)
		case strings.EqualFold(field, "progress"):
			err = dec.Decode(&st.Progress)
		case strings.EqualFold(field, "discovered_targets"):
			st.DiscoveredTargets, err = decodeScannerStatusStrings(dec, "discovered targets")
		case strings.EqualFold(field, "covered_endpoints"):
			st.CoveredEndpoints, err = decodeScannerStatusCoverage(dec)
		case strings.EqualFold(field, "coverage_warning"):
			err = dec.Decode(&st.CoverageWarning)
		default:
			err = skipScannerJSONValue(dec)
		}
		if err != nil {
			return fmt.Errorf("scanner status field %q: %w", field, err)
		}
	}
	end, err := dec.Token()
	if err != nil {
		return err
	}
	if end, ok := end.(json.Delim); !ok || end != '}' {
		return errors.New("scanner status object was not closed")
	}
	return nil
}

func decodeScannerStatusStrings(dec *json.Decoder, field string) ([]string, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '[' {
		return nil, fmt.Errorf("%s must be an array", field)
	}
	values := make([]string, 0)
	for dec.More() {
		if len(values) >= maxScannerStatusCollectionItems {
			return nil, scannerStatusCollectionLimitError(field)
		}
		var value string
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	end, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if end, ok := end.(json.Delim); !ok || end != ']' {
		return nil, fmt.Errorf("%s array was not closed", field)
	}
	return values, nil
}

func decodeScannerStatusCoverage(dec *json.Decoder) ([]types.EndpointCoverage, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '[' {
		return nil, errors.New("covered endpoints must be an array")
	}
	values := make([]types.EndpointCoverage, 0)
	for dec.More() {
		if len(values) >= maxScannerStatusCollectionItems {
			return nil, scannerStatusCollectionLimitError("covered endpoints")
		}
		var value types.EndpointCoverage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	end, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if end, ok := end.(json.Delim); !ok || end != ']' {
		return nil, errors.New("covered endpoints array was not closed")
	}
	return values, nil
}

func scannerStatusCollectionLimitError(field string) error {
	return fmt.Errorf("scanner status %s exceed %d-item limit", field, maxScannerStatusCollectionItems)
}

func skipScannerJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("unexpected JSON closing delimiter")
	}
	stack := []json.Delim{delim}
	for len(stack) > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			continue
		}
		switch delim {
		case '{', '[':
			stack = append(stack, delim)
		case '}', ']':
			want := json.Delim('{')
			if delim == ']' {
				want = '['
			}
			if stack[len(stack)-1] != want {
				return errors.New("mismatched JSON closing delimiter")
			}
			stack = stack[:len(stack)-1]
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	return nil
}

func validateScannerString(field, value string) error {
	if len(value) > maxScannerNodeStringBytes {
		return fmt.Errorf("scanner %s exceeds %d-byte limit", field, maxScannerNodeStringBytes)
	}
	return nil
}

func validateScanStatus(st types.ScanStatus) error {
	if len(st.DiscoveredTargets) > maxScannerStatusCollectionItems {
		return fmt.Errorf(
			"scanner status discovered targets exceed %d-item limit",
			maxScannerStatusCollectionItems,
		)
	}
	if len(st.CoveredEndpoints) > maxScannerStatusCollectionItems {
		return fmt.Errorf(
			"scanner status covered endpoints exceed %d-item limit",
			maxScannerStatusCollectionItems,
		)
	}
	for _, target := range st.DiscoveredTargets {
		if err := validateScannerString("discovered target", target); err != nil {
			return err
		}
	}
	for _, endpoint := range st.CoveredEndpoints {
		if err := validateScannerString("covered endpoint template id", endpoint.TemplateID); err != nil {
			return err
		}
		if err := validateScannerString("covered endpoint", endpoint.Endpoint); err != nil {
			return err
		}
	}
	if err := validateScannerString("scan id", st.ID); err != nil {
		return err
	}
	if err := validateScannerString("state", string(st.State)); err != nil {
		return err
	}
	if st.Progress != nil {
		if err := validateScannerString("progress phase", string(st.Progress.Phase)); err != nil {
			return err
		}
	}
	if err := validateScannerString("Nuclei version", st.NucleiVersion); err != nil {
		return err
	}
	if err := validateScannerString("templates commit", st.TemplatesCommit); err != nil {
		return err
	}
	if err := validateScannerString("error", st.Error); err != nil {
		return err
	}
	if err := validateScannerString("coverage warning", st.CoverageWarning); err != nil {
		return err
	}
	return nil
}

// NewScannerClient builds a client for the node at baseURL (e.g. http://scanner:8081).
func NewScannerClient(baseURL, token string) *ScannerClient {
	c := &ScannerClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
	}
	c.http = c.newHTTPClient(30 * time.Second)
	return c
}

// newHTTPClient builds an *http.Client with the given timeout, wiring in the
// client's TLS config (if any) so mTLS applies uniformly to short calls and the
// streaming results fetch alike. Redirects are returned to the caller instead of
// followed because scanner nodes have no legitimate reason to redirect the
// backend's fixed /v1 requests to another network destination.
func (c *ScannerClient) newHTTPClient(timeout time.Duration) *http.Client {
	hc := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c.tlsCfg != nil {
		hc.Transport = &http.Transport{TLSClientConfig: c.tlsCfg.Clone()}
	}
	return hc
}

func (c *ScannerClient) clientForTimeout(timeout time.Duration) *http.Client {
	if c.httpForTimeout != nil {
		return c.httpForTimeout(timeout)
	}
	return c.newHTTPClient(timeout)
}

func (c *ScannerClient) newReq(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return req, nil
}

// StartScan dispatches a scan and returns the node-local scan id.
func (c *ScannerClient) StartScan(ctx context.Context, spec types.ScanSpec) (string, error) {
	body, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	req, err := c.newReq(ctx, http.MethodPost, "/v1/scans", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("start scan: %s", statusErr(resp))
	}
	var out types.StartScanResponse
	if err := decodeScannerJSON(resp.Body, &out); err != nil {
		return "", err
	}
	if err := validateScannerString("scan id", out.ScanID); err != nil {
		return "", err
	}
	return out.ScanID, nil
}

// Status fetches a scan's current status from the node.
func (c *ScannerClient) Status(ctx context.Context, nodeScanID string) (types.ScanStatus, error) {
	req, err := c.newReq(ctx, http.MethodGet, "/v1/scans/"+nodeScanID, nil)
	if err != nil {
		return types.ScanStatus{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return types.ScanStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return types.ScanStatus{}, fmt.Errorf("status: %s", statusErr(resp))
	}
	var st types.ScanStatus
	if err := decodeScannerStatus(resp.Body, &st); err != nil {
		return types.ScanStatus{}, err
	}
	if err := validateScanStatus(st); err != nil {
		return types.ScanStatus{}, err
	}
	return st, nil
}

// Capabilities fetches the node's runtime facts (nuclei version, template
// commit). The backend polls this to derive node liveness (#98) — a failed call
// (unreachable node, non-200) marks the node unhealthy.
func (c *ScannerClient) Capabilities(ctx context.Context) (types.Capabilities, error) {
	req, err := c.newReq(ctx, http.MethodGet, "/v1/capabilities", nil)
	if err != nil {
		return types.Capabilities{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return types.Capabilities{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return types.Capabilities{}, fmt.Errorf("capabilities: %s", statusErr(resp))
	}
	var caps types.Capabilities
	if err := decodeScannerJSON(resp.Body, &caps); err != nil {
		return types.Capabilities{}, err
	}
	if err := validateScannerString("Nuclei version", caps.NucleiVersion); err != nil {
		return types.Capabilities{}, err
	}
	if err := validateScannerString("templates commit", caps.TemplatesCommit); err != nil {
		return types.Capabilities{}, err
	}
	return caps, nil
}

// ValidateTemplate asks the scanner node's pinned Nuclei binary for an
// authoritative custom-template verdict. A valid=false result is not a
// transport error; callers map it to a client-side validation response.
func (c *ScannerClient) ValidateTemplate(ctx context.Context, yaml []byte) (types.TemplateValidationResult, error) {
	req, err := c.newReq(ctx, http.MethodPost, "/v1/templates/validate", bytes.NewReader(yaml))
	if err != nil {
		return types.TemplateValidationResult{}, err
	}
	req.Header.Set("Content-Type", "application/yaml")
	resp, err := c.clientForTimeout(35 * time.Second).Do(req)
	if err != nil {
		return types.TemplateValidationResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return types.TemplateValidationResult{}, fmt.Errorf("validate template: %s", statusErr(resp))
	}
	var result types.TemplateValidationResult
	if err := decodeScannerJSON(resp.Body, &result); err != nil {
		return types.TemplateValidationResult{}, err
	}
	if result.Errors == nil {
		result.Errors = []string{}
	}
	return result, nil
}

// ValidateTemplateBatch submits a transient, verified bundle for validation in
// one Nuclei process. The node does not activate this bundle.
func (c *ScannerClient) ValidateTemplateBatch(ctx context.Context, bundle []byte) (types.TemplateBatchValidationResult, error) {
	req, err := c.newReq(ctx, http.MethodPost, "/v1/templates/validate-batch", bytes.NewReader(bundle))
	if err != nil {
		return types.TemplateBatchValidationResult{}, err
	}
	req.Header.Set("Content-Type", "application/gzip")
	resp, err := c.clientForTimeout(types.TemplateBatchValidationClientTimeout).Do(req)
	if err != nil {
		return types.TemplateBatchValidationResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return types.TemplateBatchValidationResult{}, fmt.Errorf("validate template batch: %s", statusErr(resp))
	}
	var result types.TemplateBatchValidationResult
	if err := decodeScannerJSON(resp.Body, &result); err != nil {
		return types.TemplateBatchValidationResult{}, err
	}
	if result.Failures == nil {
		result.Failures = []types.TemplateValidationFailure{}
	}
	if result.Errors == nil {
		result.Errors = []string{}
	}
	return result, nil
}

// pushBundleTimeout bounds a full-catalog bundle upload + the node's verify/
// activate. Generous: the catalog is a few MB and the node hashes every file.
const pushBundleTimeout = 5 * time.Minute

// PushBundle uploads a full-catalog template bundle to the node and returns the
// activated status (#85). The node verifies and atomically activates it; a bad
// bundle or a busy node is a non-200 surfaced as an error.
func (c *ScannerClient) PushBundle(ctx context.Context, bundle []byte) (types.TemplateBundleStatus, error) {
	req, err := c.newReq(ctx, http.MethodPost, "/v1/templates/bundle", bytes.NewReader(bundle))
	if err != nil {
		return types.TemplateBundleStatus{}, err
	}
	req.Header.Set("Content-Type", "application/gzip")
	resp, err := c.newHTTPClient(pushBundleTimeout).Do(req)
	if err != nil {
		return types.TemplateBundleStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusConflict {
			return types.TemplateBundleStatus{}, fmt.Errorf("%w: %s", ErrScannerBusy, statusErr(resp))
		}
		return types.TemplateBundleStatus{}, fmt.Errorf("push bundle: %s", statusErr(resp))
	}
	var st types.TemplateBundleStatus
	if err := decodeScannerJSON(resp.Body, &st); err != nil {
		return types.TemplateBundleStatus{}, err
	}
	if err := validateScannerString("templates commit", st.TemplatesCommit); err != nil {
		return types.TemplateBundleStatus{}, err
	}
	return st, nil
}

// Cancel asks the node to abort a running scan (it kills the nuclei process
// group). A node that no longer knows the scan (404 — already finished or the
// node restarted) is not an error: the backend has already recorded the terminal
// state, so there's nothing left to stop.
func (c *ScannerClient) Cancel(ctx context.Context, nodeScanID string) error {
	req, err := c.newReq(ctx, http.MethodPost, "/v1/scans/"+nodeScanID+"/cancel", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("cancel: %s", statusErr(resp))
	}
	return nil
}

// resultsClientTimeout bounds the entire results fetch, including streaming the
// body. It backstops the run context so a node that accepts the request but then
// dribbles or stalls the stream can't hold the fetch open indefinitely.
const resultsClientTimeout = 45 * time.Minute

// Results streams the node's JSONL results. The caller must close the reader.
// A dedicated client (with a generous timeout) is used since result sets can
// stream a while.
func (c *ScannerClient) Results(ctx context.Context, nodeScanID string) (io.ReadCloser, error) {
	req, err := c.newReq(ctx, http.MethodGet, "/v1/scans/"+nodeScanID+"/results", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.newHTTPClient(resultsClientTimeout).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("results: %s", statusErr(resp))
	}
	return resp.Body, nil
}

// Log streams the node's execution log for a scan (Nuclei's verbatim
// stdout/stderr, #94). The caller must close the reader. Like Results it uses a
// generously-timed client since the log can stream a while.
func (c *ScannerClient) Log(ctx context.Context, nodeScanID string) (io.ReadCloser, error) {
	req, err := c.newReq(ctx, http.MethodGet, "/v1/scans/"+nodeScanID+"/log", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.newHTTPClient(resultsClientTimeout).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("log: %s", statusErr(resp))
	}
	return resp.Body, nil
}

func statusErr(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(b))
	if msg == "" {
		return resp.Status
	}
	return fmt.Sprintf("%s: %s", resp.Status, msg)
}
