package browser

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// localScreenshot takes a screenshot using chromedp if available.
func (s *Scraper) localScreenshot(ctx context.Context, targetURL string, fullPage bool) (string, error) {
	// Use chromedp if local Chrome is enabled
	if s.config.UseLocalChrome {
		chrome := NewChromeDP(s.config)
		if chrome.IsAvailable() {
			return chrome.TakeScreenshot(ctx, targetURL)
		}
	}
	
	// Fallback to basic HTTP (will return an error as real screenshots need a browser)
	return "", fmt.Errorf("local screenshot requires Chrome/chromedp integration. Enable UseLocalChrome in config")
}

// localExtractContent extracts content using chromedp or HTTP fallback.
func (s *Scraper) localExtractContent(ctx context.Context, targetURL string) (string, string, error) {
	// Use chromedp if local Chrome is enabled
	if s.config.UseLocalChrome {
		chrome := NewChromeDP(s.config)
		if chrome.IsAvailable() {
			return chrome.ExtractContent(ctx, targetURL)
		}
	}

	// Fallback to basic HTTP
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, s.config.MaxContentSize))
	if err != nil {
		return "", "", err
	}

	title := extractTitle(targetURL)
	content := htmlToMarkdown(string(body))

	return content, title, nil
}

// saveScreenshot saves screenshot data to a file.
func saveScreenshot(data []byte, targetURL, dir string) (string, error) {
	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create screenshot dir: %w", err)
	}

	// Generate filename from URL
	filename := sanitizeFilename(targetURL)
	timestamp := time.Now().Format("20060102-150405")
	fullPath := filepath.Join(dir, fmt.Sprintf("%s-%s.png", timestamp, filename))

	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write screenshot: %w", err)
	}

	return fullPath, nil
}