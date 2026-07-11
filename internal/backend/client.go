package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// ScannerClient talks to one scanner node's /v1 API using a bearer service token.
type ScannerClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewScannerClient builds a client for the node at baseURL (e.g. http://scanner:8081).
func NewScannerClient(baseURL, token string) *ScannerClient {
	return &ScannerClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
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
	resp, err := (&http.Client{Timeout: resultsClientTimeout}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("results: %s", statusErr(resp))
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
