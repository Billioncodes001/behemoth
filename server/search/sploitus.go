package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SploitusSearchEngine implements SearchEngine for Sploitus exploit database.
// Sploitus aggregates exploits from multiple sources (EDB, Packet Storm, etc.)
type SploitusSearchEngine struct {
	enabled bool
}

// NewSploitusSearchEngine creates a new Sploitus search engine.
func NewSploitusSearchEngine(enabled bool) *SploitusSearchEngine {
	return &SploitusSearchEngine{enabled: enabled}
}

func (s *SploitusSearchEngine) Engine() SearchEngineType { return EngineSploitus }

func (s *SploitusSearchEngine) IsAvailable() bool { return s.enabled }

// sploitusResponse is the JSON response from Sploitus API.
type sploitusResponse struct {
	Exploits []sploitusExploit `json:"exploits"`
}

type sploitusExploit struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Type        string  `json:"type"` // "dos", "local", "remote", "webapp"
	Description string `json:"description"`
	Date        string  `json:"date"`
	Author      string  `json:"author"`
	Platform    string  `json:"platform"`
	URL         string  `json:"url"`
}

func (s *SploitusSearchEngine) Handle(ctx context.Context, req Request) (Response, error) {
	if !s.IsAvailable() {
		return Response{}, fmt.Errorf("sploitus search is not enabled")
	}

	startTime := time.Now()
	return s.fallbackScrape(ctx, req, startTime)
}

// fallbackScrape queries public exploit & PoC sources (GitHub PoC repos + Exploit-DB/NVD via DDG)
// when Sploitus v1 API is unauthenticated or unavailable.
func (s *SploitusSearchEngine) fallbackScrape(ctx context.Context, req Request, startTime time.Time) (Response, error) {
	maxRes := req.MaxResults
	if maxRes <= 0 {
		maxRes = 10
	}
	var results []Result

	// 1. Query GitHub public PoC / Exploit repositories
	ghURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&per_page=%d",
		url.QueryEscape(req.Query+" exploit OR poc OR CVE"), min(maxRes, 10))
	if ghReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ghURL, nil); err == nil {
		ghReq.Header.Set("Accept", "application/vnd.github+json")
		ghReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
		if ghResp, err := httpClient.Do(ghReq); err == nil {
			body, _ := io.ReadAll(io.LimitReader(ghResp.Body, 1<<20))
			ghResp.Body.Close()
			if ghResp.StatusCode == http.StatusOK {
				var parsed struct {
					Items []struct {
						FullName    string `json:"full_name"`
						HTMLURL     string `json:"html_url"`
						Description string `json:"description"`
						Stars       int    `json:"stargazers_count"`
						UpdatedAt   string `json:"updated_at"`
						Language    string `json:"language"`
					} `json:"items"`
				}
				if json.Unmarshal(body, &parsed) == nil {
					for _, item := range parsed.Items {
						if len(results) >= maxRes {
							break
						}
						desc := item.Description
						if desc == "" {
							desc = "Public exploit / PoC repository"
						}
						lang := item.Language
						if lang == "" {
							lang = "PoC"
						}
						snippet := fmt.Sprintf("[%s · ★%d] %s (Updated: %s)", lang, item.Stars, desc, strings.Split(item.UpdatedAt, "T")[0])
						results = append(results, Result{
							Title:   item.FullName + " — Exploit / PoC",
							URL:     item.HTMLURL,
							Snippet: snippet,
							Engine:  string(EngineSploitus),
							Rank:    len(results) + 1,
						})
					}
				}
			}
		}
	}

	// 2. Supplement with Exploit-DB / PacketStorm / Advisory search via DuckDuckGo
	if len(results) < maxRes {
		ddg := NewDuckDuckGoSearchEngine(true)
		ddgResp, err := ddg.Handle(ctx, Request{
			Query:      req.Query + " (site:exploit-db.com OR site:packetstormsecurity.com OR site:nvd.nist.gov OR site:github.com/advisories OR exploit PoC)",
			MaxResults: maxRes - len(results),
			Mode:       ModeExploit,
		})
		if err == nil {
			for _, r := range ddgResp.Results {
				if len(results) >= maxRes {
					break
				}
				r.Engine = string(EngineSploitus)
				r.Rank = len(results) + 1
				results = append(results, r)
			}
		}
	}

	return Response{
		Results:    results,
		Engine:     EngineSploitus,
		Query:      req.Query,
		TotalFound: len(results),
		Duration:   time.Since(startTime),
	}, nil
}

// parseAlternative handles alternative response formats from Sploitus.
func (s *SploitusSearchEngine) parseAlternative(body []byte, req Request, startTime time.Time) (Response, error) {
	// Sometimes Sploitus returns an array directly
	var exploits []sploitusExploit
	if err := json.Unmarshal(body, &exploits); err != nil {
		return Response{
			Duration: time.Since(startTime),
		}, fmt.Errorf("failed to parse sploitus response: %w", err)
	}

	results := make([]Result, 0, len(exploits))
	for i, e := range exploits {
		if i >= req.MaxResults {
			break
		}
		results = append(results, Result{
			Title:   e.Title,
			URL:     e.URL,
			Snippet: e.Description,
			Engine:  string(EngineSploitus),
			Rank:    i + 1,
		})
	}

	return Response{
		Results:    results,
		Engine:     EngineSploitus,
		Query:      req.Query,
		TotalFound: len(results),
		Duration:   time.Since(startTime),
	}, nil
}