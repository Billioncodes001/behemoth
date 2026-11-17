package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// GoogleSearchEngine implements SearchEngine for Google Custom Search.
type GoogleSearchEngine struct {
	apiKey string
	cseID  string
}

// NewGoogleSearchEngine creates a new Google search engine.
func NewGoogleSearchEngine(apiKey, cseID string) *GoogleSearchEngine {
	return &GoogleSearchEngine{
		apiKey: apiKey,
		cseID:  cseID,
	}
}

func (g *GoogleSearchEngine) Engine() SearchEngineType { return EngineGoogle }

func (g *GoogleSearchEngine) IsAvailable() bool {
	return g.apiKey != "" && g.cseID != ""
}

// googleResponse represents the JSON response from Google CSE API.
type googleResponse struct {
	Items []googleItem `json:"items"`
	SearchInfo struct {
		TotalResults string `json:"totalResults"`
	} `json:"searchInformation"`
}

type googleItem struct {
	Title   string `json:"title"`
	Link    string `json:"link"`
	Snippet string `json:"snippet"`
}

func (g *GoogleSearchEngine) Handle(ctx context.Context, req Request) (Response, error) {
	if !g.IsAvailable() {
		return Response{}, fmt.Errorf("google search is not configured")
	}

	startTime := time.Now()

	// Build request URL
	apiURL := "https://www.googleapis.com/customsearch/v1"
	params := url.Values{}
	params.Set("key", g.apiKey)
	params.Set("cx", g.cseID)
	params.Set("q", req.Query)
	params.Set("num", fmt.Sprintf("%d", min(req.MaxResults, 10)))

	if req.SiteFilter != "" {
		params.Set("siteSearch", req.SiteFilter)
		params.Set("siteSearchFilter", "i")
	}

	fullURL := apiURL + "?" + params.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return Response{}, fmt.Errorf("failed to create google request: %w", err)
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("google search failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return Response{}, fmt.Errorf("failed to read google response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("google API error: status %d, body: %s",
			resp.StatusCode, truncateString(string(body), 500))
	}

	var gr googleResponse
	if err := json.Unmarshal(body, &gr); err != nil {
		return Response{}, fmt.Errorf("failed to parse google response: %w", err)
	}

	results := make([]Result, 0, len(gr.Items))
	for i, item := range gr.Items {
		results = append(results, Result{
			Title:   cleanHTML(item.Title),
			URL:     item.Link,
			Snippet: cleanHTML(item.Snippet),
			Engine:  string(EngineGoogle),
			Rank:    i + 1,
		})
	}

	return Response{
		Results:    results,
		Engine:     EngineGoogle,
		Query:      req.Query,
		TotalFound: len(gr.Items),
		Duration:   time.Since(startTime),
	}, nil
}