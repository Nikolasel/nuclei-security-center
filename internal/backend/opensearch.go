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

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// OpenSearch derived findings index (#21). Postgres remains the system of
// record; OpenSearch is a search projection synced at ingest and rebuildable by
// backfill. We talk to it over its REST API with the standard library (no heavy
// client dependency — consistent with the repo's stdlib bias), so the request
// bodies are plain JSON we build and can unit-test directly.
//
// Enable it by setting OPENSEARCH_URL; unset ⇒ search reads straight from
// Postgres (default). Because the lifecycle's detection/effective state is
// derived relative to a target's latest scan, the index is refreshed per target
// after each scan completes (and fully rebuildable via backfill) — the projection
// is eventually consistent with Postgres, which stays authoritative.

// OpenSearchClient is a minimal OpenSearch REST client for the findings index.
type OpenSearchClient struct {
	baseURL string
	index   string
	user    string
	pass    string
	http    *http.Client
}

// NewOpenSearchClient builds a client for the given cluster URL and index.
// user/pass may be empty (no basic auth).
func NewOpenSearchClient(baseURL, index, user, pass string) *OpenSearchClient {
	return &OpenSearchClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		index:   index,
		user:    user,
		pass:    pass,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *OpenSearchClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	return c.http.Do(req)
}

// EnsureIndex creates the findings index with an explicit mapping if it doesn't
// exist. Idempotent: an existing index (HTTP 400 resource_already_exists) is fine.
func (c *OpenSearchClient) EnsureIndex(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodHead, "/"+c.index, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	resp, err = c.do(ctx, http.MethodPut, "/"+c.index, findingsIndexMapping)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		// A racing creator (another replica) already made it — not an error.
		if bytes.Contains(b, []byte("resource_already_exists_exception")) {
			return nil
		}
		return fmt.Errorf("create index: %s: %s", resp.Status, string(b))
	}
	return nil
}

// findingsIndexMapping keeps the analyst-facing text fields searchable and the
// facet fields exact (keyword), matching how the Postgres filters behave.
var findingsIndexMapping = map[string]any{
	"mappings": map[string]any{
		"properties": map[string]any{
			"target_id":          map[string]any{"type": "keyword"},
			"template_id":        map[string]any{"type": "keyword"},
			"name":               map[string]any{"type": "text"},
			"severity":           map[string]any{"type": "keyword"},
			"effective_severity": map[string]any{"type": "keyword"},
			"host":               map[string]any{"type": "keyword"},
			"cve":                map[string]any{"type": "keyword"},
			"tags":               map[string]any{"type": "keyword"},
			"disposition":        map[string]any{"type": "keyword"},
			"effective_state":    map[string]any{"type": "keyword"},
			"last_seen_at":       map[string]any{"type": "date"},
		},
	},
}

// severitySort ranks the effective severity so the most severe sort first, the
// same order as the Postgres list.
var severitySort = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

// buildLifecycleQuery translates a LifecycleFilter into an OpenSearch search
// body. It is a pure function (no I/O) so the filter→query mapping is unit
// tested. Substring filters (name/host/cve) use wildcard/match to mirror the
// Postgres ILIKE '%…%' behavior; facets use exact term filters.
func buildLifecycleQuery(f store.LifecycleFilter) map[string]any {
	var filters []any
	var musts []any

	term := func(field, val string) {
		filters = append(filters, map[string]any{"term": map[string]any{field: val}})
	}
	if f.TargetID != "" {
		term("target_id", f.TargetID)
	}
	if f.Disposition != "" {
		term("disposition", f.Disposition)
	}
	if f.State != "" {
		term("effective_state", f.State)
	}
	if f.Tag != "" {
		term("tags", f.Tag)
	}
	if len(f.Severities) > 0 {
		lowered := make([]string, len(f.Severities))
		for i, s := range f.Severities {
			lowered[i] = strings.ToLower(s)
		}
		filters = append(filters, map[string]any{"terms": map[string]any{"effective_severity": lowered}})
	}
	if f.Host != "" {
		filters = append(filters, map[string]any{"wildcard": map[string]any{"host": "*" + strings.ToLower(f.Host) + "*"}})
	}
	if f.CVE != "" {
		filters = append(filters, map[string]any{"wildcard": map[string]any{"cve": "*" + strings.ToLower(f.CVE) + "*"}})
	}
	if f.Query != "" {
		// name (text) OR template_id (keyword prefix), mirroring the SQL OR.
		musts = append(musts, map[string]any{"bool": map[string]any{
			"should": []any{
				map[string]any{"match": map[string]any{"name": f.Query}},
				map[string]any{"wildcard": map[string]any{"template_id": "*" + strings.ToLower(f.Query) + "*"}},
			},
			"minimum_should_match": 1,
		}})
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	boolQ := map[string]any{}
	if len(filters) > 0 {
		boolQ["filter"] = filters
	}
	if len(musts) > 0 {
		boolQ["must"] = musts
	}
	query := map[string]any{"match_all": map[string]any{}}
	if len(boolQ) > 0 {
		query = map[string]any{"bool": boolQ}
	}

	return map[string]any{
		"from":             offset,
		"size":             limit,
		"track_total_hits": true,
		"query":            query,
		// Sort most-severe first, then most-recently-seen — the Postgres order.
		"sort": []any{
			map[string]any{"_script": map[string]any{
				"type": "number",
				"script": map[string]any{
					"lang":   "painless",
					"source": "params.rank.getOrDefault(doc['effective_severity'].value, 0)",
					"params": map[string]any{"rank": severitySort},
				},
				"order": "desc",
			}},
			map[string]any{"last_seen_at": map[string]any{"order": "desc"}},
		},
	}
}

// osSearchResponse is the slice of an OpenSearch _search response we read.
type osSearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source store.LifecycleRow `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// ListLifecycle runs the filter against OpenSearch and returns the page + total.
func (c *OpenSearchClient) ListLifecycle(ctx context.Context, f store.LifecycleFilter) ([]store.LifecycleRow, int, error) {
	resp, err := c.do(ctx, http.MethodPost, "/"+c.index+"/_search", buildLifecycleQuery(f))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("search: %s: %s", resp.Status, string(b))
	}
	var out osSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, err
	}
	rows := make([]store.LifecycleRow, 0, len(out.Hits.Hits))
	for _, h := range out.Hits.Hits {
		rows = append(rows, h.Source)
	}
	return rows, out.Hits.Total.Value, nil
}

// BulkIndex indexes (upserts) a batch of lifecycle rows via the _bulk API,
// keyed by finding id so a re-index overwrites the prior projection.
func (c *OpenSearchClient) BulkIndex(ctx context.Context, rows []store.LifecycleRow) error {
	if len(rows) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range rows {
		meta := map[string]any{"index": map[string]any{"_index": c.index, "_id": fmt.Sprint(rows[i].ID)}}
		if err := enc.Encode(meta); err != nil {
			return err
		}
		if err := enc.Encode(rows[i]); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/_bulk", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bulk index: %s: %s", resp.Status, string(b))
	}
	return nil
}
