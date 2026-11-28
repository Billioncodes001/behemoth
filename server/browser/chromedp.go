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
	if c.config.ProxyProvider != nil {
		if px := c.config.ProxyProvider(); px != "" {
			opts = append(opts,
				chromedp.ProxyServer(px),
				chromedp.Flag("proxy-bypass-list", "<-loopback>;127.0.0.1;localhost;::1"),
				chromedp.Flag("ignore-certificate-errors", true),
			)
		}
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	// Navigate, wait for DOM readiness + brief SPA hydration, then capture full screenshot on taskCtx.
	if _, err := chromedp.Run(taskCtx, chromedp.Navigate(targetURL)); err != nil {
		return "", fmt.Errorf("chromedp navigate failed: %w", err)
	}
	_, _ = chromedp.Run(taskCtx, chromedp.WaitReady("body"))
	_, _ = chromedp.Run(taskCtx, chromedp.Sleep(1500*time.Millisecond))

	buf, err := chromedp.Run(taskCtx, chromedp.FullScreenshot(95))
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
	if c.config.ProxyProvider != nil {
		if px := c.config.ProxyProvider(); px != "" {
			opts = append(opts,
				chromedp.ProxyServer(px),
				chromedp.Flag("proxy-bypass-list", "<-loopback>;127.0.0.1;localhost;::1"),
				chromedp.Flag("ignore-certificate-errors", true),
			)
		}
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	// Navigate, wait for DOM + JS hydration on taskCtx (NOT outer ctx!), then extract title + visible text.
	if _, err := chromedp.Run(taskCtx, chromedp.Navigate(targetURL)); err != nil {
		return "", "", fmt.Errorf("chromedp navigate failed: %w", err)
	}
	_, _ = chromedp.Run(taskCtx, chromedp.WaitReady("body"))
	_, _ = chromedp.Run(taskCtx, chromedp.Sleep(2500*time.Millisecond))

	title, _ := chromedp.Run(taskCtx, chromedp.Title())
	content, _ := chromedp.Run(taskCtx, chromedp.Evaluate[string](`(document.body && (document.body.innerText || document.body.textContent)) ? (document.body.innerText || document.body.textContent).trim() : ""`))
	if content == "" {
		content, _ = chromedp.Run(taskCtx, chromedp.Text(`body`))
	}
	if content == "" {
		if rawHTML, err := chromedp.Run(taskCtx, chromedp.OuterHTML("html")); err == nil && rawHTML != "" {
			content = htmlToMarkdown(rawHTML)
		}
	}

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
