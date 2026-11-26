package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// FirecrawlSearchEngine implements SearchEngine for the Firecrawl search API.
// It works against the hosted API (https://api.firecrawl.dev) or any self-hosted
// Firecrawl instance (API key optional for self-hosted deployments).
type FirecrawlSearchEngine struct {
	apiKey  string
	baseURL string
	enabled bool
}

// NewFirecrawlSearchEngine creates a new Firecrawl search engine.
// An empty baseURL defaults to the hosted Firecrawl API.
func NewFirecrawlSearchEngine(apiKey, baseURL string, enabled bool) *FirecrawlSearchEngine {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.firecrawl.dev"
	}
	return &FirecrawlSearchEngine{
		apiKey:  strings.TrimSpace(apiKey),
		baseURL: baseURL,
		enabled: enabled,
	}
}

func (f *FirecrawlSearchEngine) Engine() SearchEngineType { return EngineFirecrawl }

// IsAvailable returns true when a base URL (defaulting to the hosted API) is
// usable. Unlike the old Google CSE engine, Firecrawl works without an API key
// on self-hosted instances.
func (f *FirecrawlSearchEngine) IsAvailable() bool { return f.enabled && f.baseURL != "" }

// firecrawlRequest is the JSON request body for the Firecrawl search endpoint.
type firecrawlRequest struct {
	Query          string   `json:"query"`
	Limit          int      `json:"limit"`
	Sources        []string `json:"sources,omitempty"`
	IncludeDomains []string `json:"includeDomains,omitempty"`
}

// firecrawlSearchResult is a single web/news search result.
type firecrawlSearchResult struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

// firecrawlResponse tolerates both API versions:
//   - v2: {"data": {"web": [...], "news": [...]}}
//   - v1: {"data": [{"title":..., "url":..., "description":...}]}
type firecrawlResponse struct {
	Success bool                 `json:"success"`
	Data    firecrawlDataPayload `json:"data"`
}

// firecrawlDataPayload unmarshals either an object (v2) or an array (v1).
type firecrawlDataPayload struct {
	Web  []firecrawlSearchResult `json:"web"`
	News []firecrawlSearchResult `json:"news"`
	Raw  []firecrawlSearchResult
}

func (p *firecrawlDataPayload) UnmarshalJSON(b []byte) error {
	var obj struct {
		Web  []firecrawlSearchResult `json:"web"`
		News []firecrawlSearchResult `json:"news"`
	}
	if err := json.Unmarshal(b, &obj); err == nil && (obj.Web != nil || obj.News != nil) {
		p.Web, p.News = obj.Web, obj.News
		return nil
	}
	var arr []firecrawlSearchResult
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	p.Raw = arr
	return nil
}

// results flattens the payload into a single result list (web first, then news).
func (p *firecrawlDataPayload) results() []firecrawlSearchResult {
	out := make([]firecrawlSearchResult, 0, len(p.Web)+len(p.News)+len(p.Raw))
	out = append(out, p.Web...)
	out = append(out, p.News...)
	out = append(out, p.Raw...)
	return out
}

func (f *FirecrawlSearchEngine) Handle(ctx context.Context, req Request) (Response, error) {
	if !f.IsAvailable() {
		return Response{}, fmt.Errorf("firecrawl search is not configured")
	}

	startTime := time.Now()
	maxRes := clampMaxResults(req.MaxResults, 20)

	query := strings.TrimSpace(req.Query)
	body := firecrawlRequest{
		Query:   query,
		Limit:   maxRes,
		Sources: []string{"web"},
	}
	if req.SiteFilter != "" {
		body.IncludeDomains = []string{req.SiteFilter}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal firecrawl request: %w", err)
	}

	respBody, status, err := f.post(ctx, "/v2/search", payload)
	if err != nil {
		return Response{}, fmt.Errorf("firecrawl search failed: %w", err)
	}
	// Older self-hosted builds only expose /v1/search (or reject v2's `sources` field).
	if status == http.StatusNotFound || status == http.StatusNotImplemented ||
		(status == http.StatusBadRequest && strings.Contains(strings.ToLower(string(respBody)), "sources")) {
		v1Query := query
		if req.SiteFilter != "" && !strings.Contains(strings.ToLower(v1Query), "site:") {
			v1Query = v1Query + " site:" + strings.TrimSpace(req.SiteFilter)
		}
		v1Payload, _ := json.Marshal(firecrawlRequest{
			Query: v1Query,
			Limit: maxRes,
		})
		respBody, status, err = f.post(ctx, "/v1/search", v1Payload)
		if err != nil {
			return Response{}, fmt.Errorf("firecrawl search failed: %w", err)
		}
	}
	if status != http.StatusOK {
		return Response{}, fmt.Errorf("firecrawl API error: status %d, body: %s",
			status, truncateString(string(respBody), 500))
	}

	var fr firecrawlResponse
	if err := json.Unmarshal(respBody, &fr); err != nil {
		return Response{}, fmt.Errorf("failed to parse firecrawl response: %w", err)
	}

	all := fr.Data.results()
	results := make([]Result, 0, min(len(all), maxRes))
	for i, r := range all {
		if len(results) >= maxRes {
			break
		}
		if r.URL == "" {
			continue
		}
		results = append(results, Result{
			Title:   cleanHTML(r.Title),
			URL:     r.URL,
			Snippet: cleanHTML(truncateString(r.Description, 300)),
			Engine:  string(EngineFirecrawl),
			Rank:    i + 1,
		})
	}

	return Response{
		Results:    results,
		Engine:     EngineFirecrawl,
		Query:      req.Query,
		TotalFound: len(results),
		Duration:   time.Since(startTime),
	}, nil
}

// post issues an authenticated POST against the configured Firecrawl instance.
func (f *FirecrawlSearchEngine) post(ctx context.Context, path string, payload []byte) ([]byte, int, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, f.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create firecrawl request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	if f.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+f.apiKey)
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, err := readResponseBytes(resp, 2<<20)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read firecrawl response: %w", err)
	}
	return respBody, resp.StatusCode, nil
}
