package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// SearXNGSearchEngine implements SearchEngine for self-hosted SearXNG meta-search.
type SearXNGSearchEngine struct {
	instanceURL string
	enabled     bool
}

// NewSearXNGSearchEngine creates a new SearXNG search engine.
func NewSearXNGSearchEngine(instanceURL string, enabled bool) *SearXNGSearchEngine {
	// Normalize URL
	instanceURL = strings.TrimRight(instanceURL, "/")
	return &SearXNGSearchEngine{
		instanceURL: instanceURL,
		enabled:     enabled,
	}
}

func (s *SearXNGSearchEngine) Engine() SearchEngineType { return EngineSearXNG }

func (s *SearXNGSearchEngine) IsAvailable() bool { return s.enabled && s.instanceURL != "" }

// searxngResponse is the JSON response from SearXNG API.
type searxngResponse struct {
	Results       []searxngResult `json:"results"`
	NumberResults int             `json:"number_of_results"`
}

type searxngResult struct {
	Title   string  `json:"title"`
	URL     string  `json:"url"`
	Content string  `json:"content"`
	Engine  string  `json:"engine"`
	Score   float64 `json:"score"`
}

func (s *SearXNGSearchEngine) Handle(ctx context.Context, req Request) (Response, error) {
	if !s.IsAvailable() {
		return Response{}, fmt.Errorf("searxng is not configured")
	}

	startTime := time.Now()
	maxRes := clampMaxResults(req.MaxResults, 25)

	query := strings.TrimSpace(req.Query)
	if req.SiteFilter != "" && !strings.Contains(strings.ToLower(query), "site:") {
		query = query + " site:" + strings.TrimSpace(req.SiteFilter)
	}

	cats := s.getCategories(req.Mode)
	sxResp, err := s.queryInstance(ctx, query, cats)
	if err != nil {
		return Response{}, err
	}
	if len(sxResp.Results) == 0 && cats != "general" {
		if fallbackResp, ferr := s.queryInstance(ctx, query, "general"); ferr == nil && len(fallbackResp.Results) > 0 {
			sxResp = fallbackResp
		}
	}

	results := make([]Result, 0, min(len(sxResp.Results), maxRes))
	for _, r := range sxResp.Results {
		if len(results) >= maxRes {
			break
		}
		if r.URL == "" {
			continue
		}
		srcEngine := r.Engine
		if srcEngine == "" {
			srcEngine = "meta"
		}
		results = append(results, Result{
			Title:   cleanHTML(r.Title),
			URL:     r.URL,
			Snippet: cleanHTML(truncateString(r.Content, 300)),
			Engine:  fmt.Sprintf("searxng:%s", srcEngine),
			Rank:    len(results) + 1,
		})
	}

	return Response{
		Results:    results,
		Engine:     EngineSearXNG,
		Query:      req.Query,
		TotalFound: len(results),
		Duration:   time.Since(startTime),
	}, nil
}

func (s *SearXNGSearchEngine) queryInstance(ctx context.Context, query, categories string) (*searxngResponse, error) {
	apiURL := fmt.Sprintf("%s/search", s.instanceURL)
	params := url.Values{}
	params.Set("q", query)
	params.Set("format", "json")
	if categories != "" {
		params.Set("categories", categories)
	}
	params.Set("language", "en")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create searxng request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Forwarded-For", "127.0.0.1")
	httpReq.Header.Set("X-Real-IP", "127.0.0.1")
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("searxng search failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBytes(resp, 2<<20)
	if err != nil {
		return nil, fmt.Errorf("failed to read searxng response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("searxng API error: status %d, body: %s", resp.StatusCode, truncateString(string(body), 300))
	}

	var sxResp searxngResponse
	if err := json.Unmarshal(body, &sxResp); err != nil {
		return nil, fmt.Errorf("failed to parse searxng response: %w", err)
	}
	return &sxResp, nil
}

// getCategories maps search mode to SearXNG categories.
func (s *SearXNGSearchEngine) getCategories(mode SearchMode) string {
	switch mode {
	case ModeNews:
		return "news,general"
	case ModeExploit:
		return "it,general"
	case ModeTechnical:
		return "it,general"
	case ModeOSINT:
		return "general"
	default:
		return "general"
	}
}

var (
	localSearXNGMu      sync.Mutex
	localSearXNGURL     string
	localSearXNGChecked time.Time
)

// DetectLocalSearXNG probes the local SearXNG service provisioned on this host
// (127.0.0.1:8888, localhost:8888, or Compose service searxng:8080) using a
// direct loopback client that bypasses external outbound proxies. Positive hits
// are cached for 60s; misses are cached for only 3s so newly booted containers
// are picked up immediately.
func DetectLocalSearXNG() string {
	return detectLocalSearXNG(false)
}

// DetectLocalSearXNGForce bypasses the probe cache and immediately checks whether
// the local SearXNG service is up.
func DetectLocalSearXNGForce() string {
	return detectLocalSearXNG(true)
}

func detectLocalSearXNG(force bool) string {
	localSearXNGMu.Lock()
	defer localSearXNGMu.Unlock()
	if !force && !localSearXNGChecked.IsZero() {
		ttl := 3 * time.Second
		if localSearXNGURL != "" {
			ttl = 60 * time.Second
		}
		if time.Since(localSearXNGChecked) < ttl {
			return localSearXNGURL
		}
	}
	localSearXNGChecked = time.Now()
	localSearXNGURL = ""
	candidates := []string{"http://127.0.0.1:8888"}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		candidates = append(candidates, "http://searxng:8080")
	}
	for _, base := range candidates {
		if probeSearXNGBase(base) {
			localSearXNGURL = base
			break
		}
	}
	return localSearXNGURL
}

func probeSearXNGBase(base string) bool {
	for _, path := range []string{"/healthz", "/config"} {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Real-IP", "127.0.0.1")
		resp, err := localDirectClient.Do(req)
		cancel()
		if err != nil {
			// Connection refused / unreachable on this host — no need to try /config.
			return false
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}
