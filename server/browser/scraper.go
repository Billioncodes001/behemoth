package browser

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Scraper implements Browser using an external scraper service or direct HTTP.
// Inspired by Pentagi's browser tool with scraper integration.
type Scraper struct {
	config     *Config
	scraperURL string
}

// NewScraper creates a new browser scraper.
func NewScraper(cfg *Config) *Scraper {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Scraper{
		config:     cfg,
		scraperURL: cfg.ScraperURL,
	}
}

func (s *Scraper) IsAvailable() bool {
	return s.scraperURL != "" || s.config.UseLocalChrome
}

// UpdateConfig dynamically updates the browser scraper configuration.
func (s *Scraper) UpdateConfig(scraperURL string, useLocalChrome bool) {
	s.scraperURL = scraperURL
	s.config.ScraperURL = scraperURL
	s.config.UseLocalChrome = useLocalChrome
}

// GetConfig returns a copy of the current browser configuration.
func (s *Scraper) GetConfig() Config {
	if s.config == nil {
		return *DefaultConfig()
	}
	cfg := *s.config
	cfg.ScraperURL = s.scraperURL
	if cfg.ChromePath == "" {
		cfg.ChromePath = FindChromePath()
	}
	return cfg
}

// Handle executes a browser action.
func (s *Scraper) Handle(ctx context.Context, req BrowserRequest) (BrowserResult, error) {
	startTime := time.Now()

	// Validate URL
	if req.URL == "" {
		return BrowserResult{Error: "URL is required", Duration: time.Since(startTime)}, fmt.Errorf("URL is required")
	}

	// Check for binary URLs
	if IsBinaryURL(req.URL) {
		return BrowserResult{
			URL:      req.URL,
			Action:   req.Action,
			Error:    fmt.Sprintf("URL appears to be binary content (%s)", getExtension(req.URL)),
			Duration: time.Since(startTime),
		}, nil
	}

	// Apply defaults
	if req.Timeout <= 0 {
		req.Timeout = s.config.DefaultTimeout
	}

	var result BrowserResult

	switch req.Action {
	case ActionScreenshot, ActionBoth:
		screenshotPath, err := s.takeScreenshot(ctx, req.URL, req.FullPage)
		if err != nil {
			return BrowserResult{Error: err.Error(), Duration: time.Since(startTime)}, err
		}
		result.Screenshot = screenshotPath
		result.Success = true

	case ActionContent:
		content, title, err := s.extractContent(ctx, req.URL)
		if err != nil {
			return BrowserResult{Error: err.Error(), Duration: time.Since(startTime)}, err
		}
		result.Content = content
		result.Title = title
		result.Success = true

	case ActionPDF:
		// PDF generation (simplified - would need full Chrome for real PDF)
		return BrowserResult{
			Error:    "PDF generation requires local Chrome",
			Duration: time.Since(startTime),
		}, fmt.Errorf("PDF not available without local Chrome")

	default:
		// Default to both
		screenshotPath, _ := s.takeScreenshot(ctx, req.URL, true)
		content, title, _ := s.extractContent(ctx, req.URL)

		result.Screenshot = screenshotPath
		result.Content = content
		result.Title = title
		result.Success = true
	}

	result.URL = req.URL
	result.Action = req.Action
	result.Duration = time.Since(startTime)
	return result, nil
}

// takeScreenshot captures a screenshot of a URL.
func (s *Scraper) takeScreenshot(ctx context.Context, targetURL string, fullPage bool) (string, error) {
	// If external scraper is configured, use it
	if s.scraperURL != "" {
		return s.callScraperScreenshot(ctx, targetURL, fullPage)
	}
	// Fallback to local screenshot
	return s.localScreenshot(ctx, targetURL, fullPage)
}

// callScraperScreenshot calls an external scraper service for screenshots.
func (s *Scraper) callScraperScreenshot(ctx context.Context, targetURL string, fullPage bool) (string, error) {
	scraperURL, err := url.Parse(s.scraperURL)
	if err != nil {
		return "", fmt.Errorf("invalid scraper URL: %w", err)
	}

	query := scraperURL.Query()
	query.Set("url", targetURL)
	if fullPage {
		query.Set("fullPage", "true")
	}
	scraperURL.Path = "/screenshot"
	scraperURL.RawQuery = query.Encode()

	content, err := s.callScraper(ctx, scraperURL.String())
	if err != nil {
		return "", err
	}

	if len(content) < 2048 { // Minimum image size
		return "", fmt.Errorf("screenshot too small: %d bytes", len(content))
	}

	// Save screenshot
	path, err := saveScreenshot(content, targetURL, s.config.ScreenshotDir)
	if err != nil {
		return "", fmt.Errorf("failed to save screenshot: %w", err)
	}

	return path, nil
}

// extractContent extracts page content as markdown.
func (s *Scraper) extractContent(ctx context.Context, targetURL string) (string, string, error) {
	if s.scraperURL != "" {
		return s.callScraperContent(ctx, targetURL)
	}
	return s.localExtractContent(ctx, targetURL)
}

// callScraperContent calls external scraper for content extraction.
func (s *Scraper) callScraperContent(ctx context.Context, targetURL string) (string, string, error) {
	scraperURL, err := url.Parse(s.scraperURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid scraper URL: %w", err)
	}

	query := scraperURL.Query()
	query.Set("url", targetURL)
	query.Set("format", "markdown")
	scraperURL.Path = "/content"
	scraperURL.RawQuery = query.Encode()

	content, err := s.callScraper(ctx, scraperURL.String())
	if err != nil {
		return "", "", err
	}

	// Parse title from content (simplified)
	title := extractTitle(targetURL)

	return string(content), title, nil
}

// callScraper makes an HTTP request to the scraper service.
func (s *Scraper) callScraper(ctx context.Context, scraperURL string) ([]byte, error) {
	client := &http.Client{
		Timeout: 65 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scraperURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create scraper request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scraper request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scraper returned status %d", resp.StatusCode)
	}

	content, err := io.ReadAll(io.LimitReader(resp.Body, s.config.MaxContentSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read scraper response: %w", err)
	}

	return content, nil
}

// TakeScreenshot implements Browser interface.
func (s *Scraper) TakeScreenshot(ctx context.Context, url string) (string, error) {
	path, err := s.takeScreenshot(ctx, url, true)
	return path, err
}

// ExtractContent implements Browser interface.
func (s *Scraper) ExtractContent(ctx context.Context, url string) (string, error) {
	content, _, err := s.extractContent(ctx, url)
	return content, err
}
