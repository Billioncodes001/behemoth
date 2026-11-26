package search

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BraveSearchEngine implements SearchEngine for the Brave Search API
// (https://api.search.brave.com/res/v1/web/search).
type BraveSearchEngine struct {
	apiKey  string
	enabled bool
}

// NewBraveSearchEngine creates a new Brave search engine.
func NewBraveSearchEngine(apiKey string, enabled bool) *BraveSearchEngine {
	return &BraveSearchEngine{
		apiKey:  strings.TrimSpace(apiKey),
		enabled: enabled,
	}
}

func (b *BraveSearchEngine) Engine() SearchEngineType { return EngineBrave }

func (b *BraveSearchEngine) IsAvailable() bool { return b.enabled && b.apiKey != "" }

// braveResponse is the JSON response from the Brave Search API.
type braveResponse struct {
	Web *braveWebSection `json:"web"`
}

type braveWebSection struct {
	Results []braveResult `json:"results"`
}

type braveResult struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

func (b *BraveSearchEngine) Handle(ctx context.Context, req Request) (Response, error) {
	if !b.IsAvailable() {
		return Response{}, fmt.Errorf("brave search is not configured")
	}

	startTime := time.Now()

	query := strings.TrimSpace(req.Query)
	if req.SiteFilter != "" && !strings.Contains(strings.ToLower(query), "site:") {
		query = query + " site:" + strings.TrimSpace(req.SiteFilter)
	}

	q := url.Values{}
	q.Set("q", query)
	q.Set("count", fmt.Sprintf("%d", clampMaxResults(req.MaxResults, 20)))
	q.Set("safesearch", "off")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.search.brave.com/res/v1/web/search?"+q.Encode(), nil)
	if err != nil {
		return Response{}, fmt.Errorf("failed to create brave request: %w", err)
	}
	// Do NOT manually set Accept-Encoding: gzip — Go's http.Transport adds it and
	// decompresses transparently only when Accept-Encoding is unset on the request.
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Subscription-Token", b.apiKey)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("brave search failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readResponseBytes(resp, 2<<20)
	if err != nil {
		return Response{}, fmt.Errorf("failed to read brave response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("brave API error: status %d, body: %s",
			resp.StatusCode, truncateString(string(respBody), 500))
	}

	var brResp braveResponse
	if err := json.Unmarshal(respBody, &brResp); err != nil {
		return Response{}, fmt.Errorf("failed to parse brave response: %w", err)
	}

	var rawResults []braveResult
	if brResp.Web != nil {
		rawResults = brResp.Web.Results
	}
	results := make([]Result, 0, len(rawResults))
	for i, r := range rawResults {
		results = append(results, Result{
			Title:   cleanHTML(r.Title),
			URL:     r.URL,
			Snippet: cleanHTML(truncateString(r.Description, 300)),
			Engine:  string(EngineBrave),
			Rank:    i + 1,
		})
	}

	return Response{
		Results:    results,
		Engine:     EngineBrave,
		Query:      req.Query,
		TotalFound: len(results),
		Duration:   time.Since(startTime),
	}, nil
}

// clampMaxResults bounds a requested result count to [1, max].
func clampMaxResults(n, max int) int {
	if n <= 0 {
		return 10
	}
	if n > max {
		return max
	}
	return n
}
