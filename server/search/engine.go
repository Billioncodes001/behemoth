// Package search provides multi-engine web search capabilities inspired by Pentagi.
// It supports multiple search engines with automatic fallback chains,
// AI-powered search, and exploit database integration.
package search

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SearchEngineType identifies a search engine implementation.
type SearchEngineType string

const (
	// EngineGoogle is Google Custom Search.
	EngineGoogle SearchEngineType = "google"
	// EngineDuckDuckGo is DuckDuckGo HTML search.
	EngineDuckDuckGo SearchEngineType = "duckduckgo"
	// EngineTavily is Tavily AI-powered search.
	EngineTavily SearchEngineType = "tavily"
	// EngineSearXNG is self-hosted SearXNG meta-search.
	EngineSearXNG SearchEngineType = "searxng"
	// EngineSploitus is Sploitus exploit database search.
	EngineSploitus SearchEngineType = "sploitus"
)

// SearchMode defines the type of search to perform.
type SearchMode string

const (
	// ModeGeneral is general web search.
	ModeGeneral SearchMode = "general"
	// ModeNews searches news sources.
	ModeNews SearchMode = "news"
	// ModeExploit searches exploit databases specifically.
	ModeExploit SearchMode = "exploit"
	// ModeTechnical searches technical documentation.
	ModeTechnical SearchMode = "technical"
	// ModeOSINT performs OSINT-focused search.
	ModeOSINT SearchMode = "osint"
)

// Request represents a search query with options.
type Request struct {
	Query      string        `json:"query"`
	MaxResults int           `json:"max_results,omitempty"`
	Mode       SearchMode    `json:"mode,omitempty"`
	Engine     string        `json:"engine,omitempty"`      // optional specific engine override
	Timeout    time.Duration `json:"timeout,omitempty"`
	SiteFilter string        `json:"site_filter,omitempty"` // e.g., "example.com"
}

// Result represents a single search result.
type Result struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
	Engine  string `json:"engine"`
	Rank    int    `json:"rank"`
}

// Response contains search results from an engine.
type Response struct {
	Results    []Result       `json:"results"`
	Engine     SearchEngineType `json:"engine"`
	Query      string         `json:"query"`
	TotalFound int            `json:"total_found,omitempty"`
	Duration   time.Duration  `json:"duration"`
	Error      error          `json:"-"`
}

// SearchEngine is the interface that all search engines must implement.
type SearchEngine interface {
	// Engine returns the engine type identifier.
	Engine() SearchEngineType
	// IsAvailable returns true if the engine is configured and usable.
	IsAvailable() bool
	// Handle executes a search request and returns results.
	Handle(ctx context.Context, req Request) (Response, error)
}

// Config holds configuration for all search engines.
type Config struct {
	Google struct {
		APIKey  string `json:"api_key"`
		CSEID   string `json:"cse_id"`
		Enabled bool   `json:"enabled"`
	} `json:"google"`

	DuckDuckGo struct {
		Enabled bool `json:"enabled"`
	} `json:"duckduckgo"`

	Tavily struct {
		APIKey  string `json:"api_key"`
		Enabled bool   `json:"enabled"`
	} `json:"tavily"`

	SearXNG struct {
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	} `json:"searxng"`

	Sploitus struct {
		Enabled bool `json:"enabled"`
	} `json:"sploitus"`

	// DefaultTimeout is the default search timeout.
	DefaultTimeout time.Duration `json:"default_timeout"`

	// MaxResults is the default maximum results per engine.
	MaxResults int `json:"max_results"`
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	cfg := &Config{
		DefaultTimeout: 30 * time.Second,
		MaxResults:     10,
	}
	cfg.DuckDuckGo.Enabled = true // DDG works without API key
	cfg.Sploitus.Enabled = true   // Sploitus works without API key
	return cfg
}

// SearchResult is the aggregated response from multiple engines.
type SearchResult struct {
	Query        string        `json:"query"`
	Mode         SearchMode    `json:"mode"`
	Results      []Result      `json:"results"`
	EnginesUsed  []string      `json:"engines_used"`
	Warnings     []string      `json:"warnings,omitempty"`
	TotalResults int           `json:"total_results"`
	Duration     time.Duration `json:"duration"`
	QueryTimeMS  int64         `json:"query_time_ms"`
	Timestamp    time.Time     `json:"timestamp"`
}

// ToJSON serializes the search result to JSON.
func (sr *SearchResult) ToJSON() (string, error) {
	data, err := json.MarshalIndent(sr, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal search result: %w", err)
	}
	return string(data), nil
}

// ToMarkdown converts search results to markdown format for LLM consumption.
func (sr *SearchResult) ToMarkdown() string {
	var md string
	md += fmt.Sprintf("# Search Results: %s\n\n", sr.Query)
	md += fmt.Sprintf("**Mode:** %s | **Engines:** %v | **Results:** %d | **Time:** %s\n\n",
		sr.Mode, sr.EnginesUsed, len(sr.Results), sr.Duration.Round(time.Millisecond))

	for i, r := range sr.Results {
		md += fmt.Sprintf("## %d. %s\n", i+1, r.Title)
		md += fmt.Sprintf("- **URL:** %s\n", r.URL)
		if r.Snippet != "" {
			md += fmt.Sprintf("- **Snippet:** %s\n", r.Snippet)
		}
		md += fmt.Sprintf("- **Source:** %s\n\n", r.Engine)
	}
	return md
}

// NewRequest creates a new search request with defaults applied.
func NewRequest(query string, mode SearchMode) Request {
	return Request{
		Query:      query,
		Mode:       mode,
		MaxResults: 10,
		Timeout:    30 * time.Second,
	}
}

// httpClient is a shared HTTP client for search requests.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}