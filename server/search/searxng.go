package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	// Build request URL
	apiURL := fmt.Sprintf("%s/search", s.instanceURL)
	params := url.Values{}
	params.Set("q", req.Query)
	params.Set("format", "json")
	params.Set("categories", s.getCategories(req.Mode))
	params.Set("language", "en")

	fullURL := apiURL + "?" + params.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return Response{}, fmt.Errorf("failed to create searxng request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("searxng search failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return Response{}, fmt.Errorf("failed to read searxng response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("searxng API error: status %d", resp.StatusCode)
	}

	var sxResp searxngResponse
	if err := json.Unmarshal(body, &sxResp); err != nil {
		return Response{}, fmt.Errorf("failed to parse searxng response: %w", err)
	}

	results := make([]Result, 0, min(len(sxResp.Results), req.MaxResults))
	for i, r := range sxResp.Results {
		if i >= req.MaxResults {
			break
		}
		results = append(results, Result{
			Title:   r.Title,
			URL:     r.URL,
			Snippet: r.Content,
			Engine:  fmt.Sprintf("searxng:%s", r.Engine), // Show source engine
			Rank:    i + 1,
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

// getCategories maps search mode to SearXNG categories.
func (s *SearXNGSearchEngine) getCategories(mode SearchMode) string {
	switch mode {
	case ModeNews:
		return "news"
	case ModeExploit:
		return "it,science" // IT and science for exploits
	case ModeTechnical:
		return "it,science"
	case ModeOSINT:
		return "general,social media"
	default:
		return "general"
	}
}

var (
	localSearXNGMu      sync.Mutex
	localSearXNGURL     string
	localSearXNGChecked time.Time
)

// DetectLocalSearXNG probes the well-known local SearXNG endpoint provisioned
// by setup.sh (Docker container bound to 127.0.0.1:8888). The result is cached
// for 60 seconds so per-request probes stay cheap. Returns "" when no local
// instance answers.
func DetectLocalSearXNG() string {
	localSearXNGMu.Lock()
	defer localSearXNGMu.Unlock()
	if !localSearXNGChecked.IsZero() && time.Since(localSearXNGChecked) < 60*time.Second {
		return localSearXNGURL
	}
	localSearXNGChecked = time.Now()
	localSearXNGURL = ""
	for _, base := range []string{"http://127.0.0.1:8888", "http://localhost:8888"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := httpClient.Do(req)
		cancel()
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			localSearXNGURL = base
			break
		}
	}
	return localSearXNGURL
}
