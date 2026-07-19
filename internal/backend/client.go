package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// ScannerClient talks to one scanner node's /v1 API using a bearer service token.
// When tlsCfg is set (per-node mTLS, #26) it is applied to every request the
// client makes — including the long-lived results fetch — so a node in an
// untrusted segment is reached over a mutually-authenticated connection.
type ScannerClient struct {
	baseURL string
	token   string
	tlsCfg  *tls.Config
	http    *http.Client
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
// streaming results fetch alike.
func (c *ScannerClient) newHTTPClient(timeout time.Duration) *http.Client {
	hc := &http.Client{Timeout: timeout}
	if c.tlsCfg != nil {
		hc.Transport = &http.Transport{TLSClientConfig: c.tlsCfg.Clone()}
	}
	return hc
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
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
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return types.Capabilities{}, err
	}
	return caps, nil
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
