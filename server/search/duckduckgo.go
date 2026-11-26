package search

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DuckDuckGoSearchEngine implements SearchEngine for DuckDuckGo HTML.
// Uses the HTML version which doesn't require an API key.
type DuckDuckGoSearchEngine struct {
	enabled bool
}

// NewDuckDuckGoSearchEngine creates a new DDG search engine.
func NewDuckDuckGoSearchEngine(enabled bool) *DuckDuckGoSearchEngine {
	return &DuckDuckGoSearchEngine{enabled: enabled}
}

func (d *DuckDuckGoSearchEngine) Engine() SearchEngineType { return EngineDuckDuckGo }

func (d *DuckDuckGoSearchEngine) IsAvailable() bool { return d.enabled }

// ddgResultRegex parses DDG HTML and DDG Lite results.
var (
	ddgResultRegex = regexp.MustCompile(`(?s)<h2 class="result__title"[^>]*>\s*<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>\s*</h2>.*?(?:<a[^>]*class="result__snippet"[^>]*>(.*?)</a>|<div[^>]*class="result__snippet"[^>]*>(.*?)</div>)`)
	ddgTitleLinkRe = regexp.MustCompile(`(?s)<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>`)
	ddgSnippetRe   = regexp.MustCompile(`(?s)class="result__snippet"[^>]*>(.*?)</(?:a|div)>`)
	ddgLiteLinkRe  = regexp.MustCompile(`(?s)<a[^>]*href="([^"]+)"[^>]*class=['"]result-link['"][^>]*>(.*?)</a>`)
	ddgLiteSnipRe  = regexp.MustCompile(`(?s)<td[^>]*class=['"]result-snippet['"][^>]*>(.*?)</td>`)
)

func (d *DuckDuckGoSearchEngine) Handle(ctx context.Context, req Request) (Response, error) {
	if !d.IsAvailable() {
		return Response{}, fmt.Errorf("duckduckgo search is not enabled")
	}

	startTime := time.Now()

	q := strings.TrimSpace(req.Query)
	if req.SiteFilter != "" && !strings.Contains(strings.ToLower(q), "site:") {
		q = "site:" + strings.TrimSpace(req.SiteFilter) + " " + q
	} else {
		switch req.Mode {
		case ModeExploit:
			if !strings.Contains(strings.ToLower(q), "exploit") && !strings.Contains(strings.ToLower(q), "cve") && !strings.Contains(strings.ToLower(q), "poc") {
				q = q + " exploit OR PoC OR vulnerability"
			}
		case ModeTechnical:
			if !strings.Contains(strings.ToLower(q), "docs") && !strings.Contains(strings.ToLower(q), "documentation") {
				q = q + " documentation"
			}
		case ModeOSINT:
			if !strings.Contains(strings.ToLower(q), "osint") && !strings.Contains(strings.ToLower(q), "site:") {
				q = q + " osint"
			}
		}
	}

	// Query DDG Lite first (avoids html.duckduckgo.com 202 anti-bot challenges),
	// falling back to html.duckduckgo.com if needed.
	results, err := d.fetchDDGEndpoint(ctx, "https://lite.duckduckgo.com/lite/", "https://lite.duckduckgo.com", q, req.MaxResults)
	if len(results) == 0 {
		if htmlRes, herr := d.fetchDDGEndpoint(ctx, "https://html.duckduckgo.com/html/", "https://html.duckduckgo.com", q, req.MaxResults); len(htmlRes) > 0 {
			results = htmlRes
			err = nil
		} else if err == nil {
			err = herr
		}
	}
	if err != nil && len(results) == 0 {
		return Response{}, err
	}

	return Response{
		Results:    results,
		Engine:     EngineDuckDuckGo,
		Query:      req.Query,
		TotalFound: len(results),
		Duration:   time.Since(startTime),
	}, nil
}

func (d *DuckDuckGoSearchEngine) fetchDDGEndpoint(ctx context.Context, apiURL, origin, q string, maxResults int) ([]Result, error) {
	formData := url.Values{}
	formData.Set("q", q)
	formData.Set("kl", "wt-wt")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create ddg request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Origin", origin)
	httpReq.Header.Set("Referer", origin+"/")
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ddg search failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBytes(resp, 2<<20) // 2MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read ddg response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("ddg API error: status %d", resp.StatusCode)
	}

	return d.parseResults(string(body), maxResults), nil
}

// parseResults extracts search results from DDG HTML response.
func (d *DuckDuckGoSearchEngine) parseResults(htmlBody string, maxResults int) []Result {
	if maxResults <= 0 {
		maxResults = 10
	}
	matches := ddgResultRegex.FindAllStringSubmatch(htmlBody, -1)
	if len(matches) == 0 {
		if alt := d.parseResultsAlt(htmlBody, maxResults); len(alt) > 0 {
			return alt
		}
		return d.parseResultsLite(htmlBody, maxResults)
	}

	results := make([]Result, 0, min(len(matches), maxResults))
	for _, m := range matches {
		if len(results) >= maxResults {
			break
		}
		cleanURL := extractDDGURL(m[1])
		if cleanURL == "" || strings.Contains(cleanURL, "duckduckgo.com/y.js") {
			continue
		}
		snippet := m[3]
		if snippet == "" && len(m) > 4 {
			snippet = m[4]
		}
		results = append(results, Result{
			Title:   cleanHTML(m[2]),
			URL:     cleanURL,
			Snippet: cleanHTML(snippet),
			Engine:  string(EngineDuckDuckGo),
			Rank:    len(results) + 1,
		})
	}
	return results
}

// parseResultsAlt handles alternative DDG HTML format by scanning result__a links.
func (d *DuckDuckGoSearchEngine) parseResultsAlt(htmlBody string, maxResults int) []Result {
	var results []Result
	titleMatches := ddgTitleLinkRe.FindAllStringSubmatchIndex(htmlBody, -1)
	for i, idx := range titleMatches {
		if len(results) >= maxResults {
			break
		}
		rawURL := htmlBody[idx[2]:idx[3]]
		rawTitle := htmlBody[idx[4]:idx[5]]
		cleanURL := extractDDGURL(rawURL)
		if cleanURL == "" || strings.Contains(cleanURL, "duckduckgo.com/y.js") {
			continue
		}
		endIdx := len(htmlBody)
		if i+1 < len(titleMatches) {
			endIdx = titleMatches[i+1][0]
		}
		block := htmlBody[idx[0]:endIdx]
		var snippet string
		if sm := ddgSnippetRe.FindStringSubmatch(block); len(sm) > 1 {
			snippet = cleanHTML(sm[1])
		}
		results = append(results, Result{
			Title:   cleanHTML(rawTitle),
			URL:     cleanURL,
			Snippet: snippet,
			Engine:  string(EngineDuckDuckGo),
			Rank:    len(results) + 1,
		})
	}
	return results
}

// parseResultsLite extracts search results from DuckDuckGo Lite HTML markup.
func (d *DuckDuckGoSearchEngine) parseResultsLite(htmlBody string, maxResults int) []Result {
	var results []Result
	linkMatches := ddgLiteLinkRe.FindAllStringSubmatchIndex(htmlBody, -1)
	for i, idx := range linkMatches {
		if len(results) >= maxResults {
			break
		}
		rawURL := htmlBody[idx[2]:idx[3]]
		rawTitle := htmlBody[idx[4]:idx[5]]
		cleanURL := extractDDGURL(rawURL)
		if cleanURL == "" || strings.Contains(cleanURL, "duckduckgo.com/y.js") {
			continue
		}
		endIdx := len(htmlBody)
		if i+1 < len(linkMatches) {
			endIdx = linkMatches[i+1][0]
		}
		block := htmlBody[idx[0]:endIdx]
		var snippet string
		if sm := ddgLiteSnipRe.FindStringSubmatch(block); len(sm) > 1 {
			snippet = cleanHTML(sm[1])
		}
		results = append(results, Result{
			Title:   cleanHTML(rawTitle),
			URL:     cleanURL,
			Snippet: snippet,
			Engine:  string(EngineDuckDuckGo),
			Rank:    len(results) + 1,
		})
	}
	return results
}

// extractDDGURL removes DDG redirect wrapper from URLs.
func extractDDGURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if strings.HasPrefix(rawURL, "//") {
		rawURL = "https:" + rawURL
	}
	if strings.Contains(rawURL, "uddg=") {
		u, err := url.Parse(rawURL)
		if err == nil {
			if actualURL := u.Query().Get("uddg"); actualURL != "" {
				return actualURL
			}
		}
	}
	return rawURL
}
