// Package browser provides web browser automation capabilities inspired by Pentagi.
package browser

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Action defines the type of browser action to perform.
type Action string

const (
	// ActionScreenshot captures a full-page screenshot.
	ActionScreenshot Action = "screenshot"
	// ActionContent extracts page content as markdown.
	ActionContent Action = "content"
	// ActionBoth captures screenshot AND extracts content.
	ActionBoth Action = "both"
	// ActionPDF generates PDF of the page.
	ActionPDF Action = "pdf"
)

// BrowserRequest is a request to perform a browser action.
type BrowserRequest struct {
	URL          string        `json:"url"`
	Action       Action        `json:"action"`
	FullPage     bool          `json:"full_page,omitempty"`
	Width        int           `json:"width,omitempty"`
	Height       int           `json:"height,omitempty"`
	Timeout      time.Duration `json:"timeout,omitempty"`
	WaitSelector string        `json:"wait_selector,omitempty"` // CSS selector to wait for
	UserAgent    string        `json:"user_agent,omitempty"`
}

// BrowserResult contains the result of a browser action.
type BrowserResult struct {
	Success    bool          `json:"success"`
	URL        string        `json:"url"`
	Action     Action        `json:"action"`
	Screenshot string        `json:"screenshot_path,omitempty"` // Path or base64
	Content    string        `json:"content,omitempty"`         // Markdown content
	Title      string        `json:"title,omitempty"`
	Duration   time.Duration `json:"duration"`
	Error      string        `json:"error,omitempty"`
	StatusCode int           `json:"status_code,omitempty"`
}

// Browser is the main interface for browser automation.
type Browser interface {
	// IsAvailable returns true if the browser service is configured.
	IsAvailable() bool
	// Handle executes a browser action and returns the result.
	Handle(ctx context.Context, req BrowserRequest) (BrowserResult, error)
	// TakeScreenshot captures a screenshot of a URL.
	TakeScreenshot(ctx context.Context, url string) (string, error)
	// ExtractContent extracts page content as markdown.
	ExtractContent(ctx context.Context, url string) (string, error)
}

// Config holds browser configuration.
type Config struct {
	// ScraperURL is the URL of an external scraper service (like Pentagi's).
	ScraperURL string `json:"scraper_url"`

	// UseLocalChrome uses local headless Chrome via chromedp.
	UseLocalChrome bool `json:"use_local_chrome"`

	// ChromePath is the path to Chrome/Chromium binary.
	ChromePath string `json:"chrome_path"`

	// ScreenshotDir is where screenshots are stored.
	ScreenshotDir string `json:"screenshot_dir"`

	// DefaultTimeout is the default operation timeout.
	DefaultTimeout time.Duration `json:"default_timeout"`

	// MaxContentSize is the max content size in bytes.
	MaxContentSize int64 `json:"max_content_size"`

	// ProxyProvider optionally returns the active HTTP/SOCKS proxy URL for outbound navigation.
	ProxyProvider func() string `json:"-"`
}

// DefaultConfig returns sensible defaults for browser config.
func DefaultConfig() *Config {
	return &Config{
		UseLocalChrome: true,
		ScreenshotDir:  "./screenshots",
		DefaultTimeout: 60 * time.Second,
		MaxContentSize: 10 * 1024 * 1024, // 10MB
	}
}

// NonHTMLExtensions are URL suffixes that point to non-HTML resources.
var NonHTMLExtensions = []string{
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
	".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg",
	".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav",
	".exe", ".bin", ".dll", ".so", ".dmg", ".apk",
}

// IsBinaryURL returns true if URL points to known non-HTML resource.
func IsBinaryURL(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	if idx := strings.Index(lower, "?"); idx != -1 {
		lower = lower[:idx]
	}
	for _, ext := range NonHTMLExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// httpClient for browser operations.
var browserClient = &http.Client{
	Timeout: 65 * time.Second,
}
