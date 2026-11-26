package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TavilySearchEngine implements SearchEngine for Tavily AI-powered search.
// Tavily provides optimized search results for AI/LLM applications.
type TavilySearchEngine struct {
	apiKey  string
	enabled bool
}

// NewTavilySearchEngine creates a new Tavily search engine.
func NewTavilySearchEngine(apiKey string, enabled bool) *TavilySearchEngine {
	return &TavilySearchEngine{
		apiKey:  apiKey,
		enabled: enabled,
	}
}

func (t *TavilySearchEngine) Engine() SearchEngineType { return EngineTavily }

func (t *TavilySearchEngine) IsAvailable() bool { return t.enabled && t.apiKey != "" }

// tavilyRequest is the JSON request body for Tavily API.
type tavilyRequest struct {
	Query             string `json:"query"`
	APIKey            string `json:"api_key"`
	MaxResults        int    `json:"max_results"`
	SearchDepth       string `json:"search_depth,omitempty"` // "basic" or "advanced"
	IncludeAnswer     bool   `json:"include_answer,omitempty"`
	IncludeRawContent bool   `json:"include_raw_content,omitempty"`
	IncludeImages     bool   `json:"include_images,omitempty"`
}

// tavilyResponse is the JSON response from Tavily API.
type tavilyResponse struct {
	Answer       string         `json:"answer"`
	Results      []tavilyResult `json:"results"`
	ResponseTime float64        `json:"response_time"`
}

type tavilyResult struct {
	Title   string  `json:"title"`
	URL     string  `json:"url"`
	Content string  `json:"content"`
	Score   float64 `json:"score"`
}

func (t *TavilySearchEngine) Handle(ctx context.Context, req Request) (Response, error) {
	if !t.IsAvailable() {
		return Response{}, fmt.Errorf("tavily search is not configured")
	}

	startTime := time.Now()

	// Determine search depth based on mode
	searchDepth := "basic"
	if req.Mode == ModeExploit || req.Mode == ModeTechnical {
		searchDepth = "advanced"
	}

	tavilyReq := tavilyRequest{
		Query:             req.Query,
		APIKey:            t.apiKey,
		MaxResults:        min(req.MaxResults, 10),
		SearchDepth:       searchDepth,
		IncludeAnswer:     true,
		IncludeRawContent: false,
	}

	bodyBytes, err := json.Marshal(tavilyReq)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal tavily request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.tavily.com/search", bytes.NewReader(bodyBytes))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create tavily request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("tavily search failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readResponseBytes(resp, 2<<20)
	if err != nil {
		return Response{}, fmt.Errorf("failed to read tavily response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("tavily API error: status %d, body: %s",
			resp.StatusCode, truncateString(string(respBody), 500))
	}

	var tvResp tavilyResponse
	if err := json.Unmarshal(respBody, &tvResp); err != nil {
		return Response{}, fmt.Errorf("failed to parse tavily response: %w", err)
	}

	results := make([]Result, 0, len(tvResp.Results))
	for i, r := range tvResp.Results {
		results = append(results, Result{
			Title:   r.Title,
			URL:     r.URL,
			Snippet: truncateString(r.Content, 300), // Tavily returns full content
			Engine:  string(EngineTavily),
			Rank:    i + 1,
		})
	}

	// Prepend answer as first result if available
	if tvResp.Answer != "" {
		answerResult := Result{
			Title:   "AI Answer Summary",
			URL:     "",
			Snippet: tvResp.Answer,
			Engine:  string(EngineTavily),
			Rank:    0,
		}
		results = append([]Result{answerResult}, results...)
	}

	return Response{
		Results:    results,
		Engine:     EngineTavily,
		Query:      req.Query,
		TotalFound: len(results),
		Duration:   time.Since(startTime),
	}, nil
}
