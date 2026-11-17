package browser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
)

// ChromeDP is a browser implementation using chromedp for local Chrome control.
type ChromeDP struct {
	config *Config
}

// NewChromeDP creates a new chromedp-based browser instance.
func NewChromeDP(cfg *Config) *ChromeDP {
	return &ChromeDP{config: cfg}
}

// IsAvailable returns true if Chrome/chromedp can be used.
func (c *ChromeDP) IsAvailable() bool {
	return c.config.UseLocalChrome
}

// TakeScreenshot captures a screenshot of a URL using headless Chrome.
func (c *ChromeDP) TakeScreenshot(ctx context.Context, targetURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.DefaultTimeout)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Headless,
	)

	if c.config.ChromePath != "" {
		opts = append(opts, chromedp.ExecPath(c.config.ChromePath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	// First run to start the browser (don't use timeout here)
	initCtx := taskCtx
	
	// Navigate first
	if _, err := chromedp.Run(initCtx, chromedp.Navigate(targetURL)); err != nil {
		return "", fmt.Errorf("chromedp navigate failed: %w", err)
	}

	// Wait and take screenshot
	buf, err := chromedp.Run(ctx, chromedp.FullScreenshot(100))
	if err != nil {
		return "", fmt.Errorf("chromedp screenshot failed: %w", err)
	}

	path, err := saveScreenshot(buf, targetURL, c.config.ScreenshotDir)
	if err != nil {
		return "", fmt.Errorf("failed to save screenshot: %w", err)
	}

	return path, nil
}

// ExtractContent extracts page content as text using Chrome.
func (c *ChromeDP) ExtractContent(ctx context.Context, targetURL string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.DefaultTimeout)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Headless,
	)

	if c.config.ChromePath != "" {
		opts = append(opts, chromedp.ExecPath(c.config.ChromePath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	// Navigate first
	if _, err := chromedp.Run(taskCtx, chromedp.Navigate(targetURL)); err != nil {
		return "", "", fmt.Errorf("chromedp navigate failed: %w", err)
	}

	// Get title and content
	title, _ := chromedp.Run(ctx, chromedp.Title())
	content, _ := chromedp.Run(ctx, chromedp.Text(`body`))

	return content, title, nil
}

// Handle executes a browser action using chromedp.
func (c *ChromeDP) Handle(ctx context.Context, req BrowserRequest) (BrowserResult, error) {
	start := time.Now()
	result := BrowserResult{
		URL:    req.URL,
		Action: req.Action,
	}

	switch req.Action {
	case ActionScreenshot, ActionBoth:
		path, err := c.TakeScreenshot(ctx, req.URL)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		result.Screenshot = path
		result.Success = true

	case ActionContent:
		content, title, err := c.ExtractContent(ctx, req.URL)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		result.Content = content
		result.Title = title
		result.Success = true

	default:
		return result, fmt.Errorf("unsupported action: %s", req.Action)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// FindChromePath attempts to find Chrome/Chromium binary on the system.
func FindChromePath() string {
	// Common Chrome/Chromium paths to check
	candidates := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium-browser",
		"/usr/bin/chromium",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Check PATH
	if path, err := filepath.Abs("google-chrome"); err == nil {
		if _, statErr := os.Stat(path); statErr == nil {
			return path
		}
	}

	return ""
}