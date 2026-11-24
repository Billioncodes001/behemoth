package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// XSSVerifyRequest describes a DOM-XSS execution verification run.
type XSSVerifyRequest struct {
	// URL is the target URL. If Param is set, the payload is appended to this
	// URL as a query parameter (URL-encoded). If Param is empty the caller is
	// expected to have embedded the payload in the URL themselves.
	URL     string
	Param   string
	Payload string
	Timeout time.Duration
}

// XSSVerifyResult reports what actually happened inside the headless browser
// when the payload executed — the evidence a finding needs.
type XSSVerifyResult struct {
	URL             string        `json:"url"`
	Payload         string        `json:"payload"`
	Confirmed       bool          `json:"confirmed"`
	DialogFired     bool          `json:"dialog_fired"`
	DialogMessage   string        `json:"dialog_message,omitempty"`
	DOMMarker       bool          `json:"dom_marker"`
	ReflectionRaw   bool          `json:"reflection_raw"` // payload appears unescaped in live DOM
	ConsoleMessages []string      `json:"console_messages,omitempty"`
	Duration        time.Duration `json:"duration"`
	Evidence        string        `json:"evidence"`
	Error           string        `json:"error,omitempty"`
}

// defaultXSSTestPayload sets a window marker inside the same event handler that
// fires the alert, so DOM confirmation works even when dialogs are suppressed.
const defaultXSSTestPayload = `<svg/onload="window.__behemothXss=true;alert('behemoth_xss_probe')">`

// VerifyXSS executes a JS payload against a URL in headless Chrome and reports
// whether it demonstrably executed (alert dialog fired, DOM marker set, and/or
// raw reflection in the live DOM). This is the automated equivalent of the
// manual "paste it into a browser and watch for the alert" XSS verification.
func (c *ChromeDP) VerifyXSS(ctx context.Context, req XSSVerifyRequest) (XSSVerifyResult, error) {
	start := time.Now()
	res := XSSVerifyResult{Payload: req.Payload}

	if req.URL == "" {
		return res, fmt.Errorf("url is required")
	}
	if res.Payload == "" {
		res.Payload = defaultXSSTestPayload
	}
	target := buildXSSURL(req.URL, req.Param, res.Payload)
	res.URL = target

	if req.Timeout <= 0 {
		req.Timeout = 30 * time.Second
	}
	if req.Timeout > 90*time.Second {
		req.Timeout = 90 * time.Second
	}

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
	return c.runXSSProbe(ctx, req, res, opts, start)
}

// dismissDialogAction accepts (closes) an open JavaScript dialog.
func dismissDialogAction() chromedp.Action[chromedp.Void] {
	return chromedp.Func(func(c context.Context, t *chromedp.Target) error {
		_, err := cdp.Call(c, t, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: true})
		return err
	})
}

// runXSSProbe launches the browser, injects hooks, navigates and inspects.
func (c *ChromeDP) runXSSProbe(ctx context.Context, req XSSVerifyRequest, res XSSVerifyResult, opts []chromedp.ExecAllocatorOption, start time.Time) (XSSVerifyResult, error) {
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()
	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()
	runCtx, runCancel := context.WithTimeout(taskCtx, req.Timeout)
	defer runCancel()

	chromedp.Listen(runCtx, func(ev any) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			res.DialogFired = true
			res.DialogMessage = e.Message
			// Dismiss from a separate goroutine so the page keeps loading and
			// other probes can run (per chromedp's documented dialog pattern).
			go func() {
				_ = chromedp.Do(runCtx, dismissDialogAction())
			}()
		case *runtime.EventConsoleAPICalled:
			for _, arg := range e.Args {
				if s := arg.Value; len(s) > 0 {
					res.ConsoleMessages = append(res.ConsoleMessages, string(s))
				}
			}
		}
	})

	if err := chromedp.Do(runCtx,
		chromedp.Navigate(res.URL),
		chromedp.Sleep(2500*time.Millisecond),
	); err != nil {
		res.Error = err.Error()
		res.Duration = time.Since(start)
		// Navigation errors are common for payload URLs (bad gateways etc.);
		// report them but keep whatever signals already fired.
		if res.DialogFired || res.DOMMarker {
			res.Confirmed = true
			res.Evidence = xssEvidence(&res)
		}
		return res, nil
	}

	var domMarker, rawReflection bool
	domMarker, evalErr := chromedp.Run(runCtx, chromedp.Evaluate[bool](`window.__behemothXss === true`))
	if evalErr != nil {
		res.Error = evalErr.Error()
	}
	rawReflection, evalErr = chromedp.Run(runCtx, chromedp.Evaluate[bool](jsReflectionCheck(res.Payload)))
	if evalErr != nil {
		res.Error = evalErr.Error()
	}
	res.DOMMarker = domMarker
	res.ReflectionRaw = rawReflection

	res.Confirmed = res.DialogFired || res.DOMMarker
	res.Duration = time.Since(start)
	res.Evidence = xssEvidence(&res)
	return res, nil
}

// VerifyXSS routes XSS verification through local Chrome; the external scraper
// service cannot execute JS event hooks, so it is not supported here.
func (s *Scraper) VerifyXSS(ctx context.Context, req XSSVerifyRequest) (XSSVerifyResult, error) {
	if s.config.UseLocalChrome {
		chrome := NewChromeDP(s.config)
		if chrome.IsAvailable() {
			return chrome.VerifyXSS(ctx, req)
		}
	}
	return XSSVerifyResult{}, fmt.Errorf("XSS execution verification requires local Chrome (enable browser_use_local_chrome)")
}

// buildXSSURL appends the payload as an encoded query parameter when Param is set.
func buildXSSURL(base, param, payload string) string {
	if strings.TrimSpace(param) == "" {
		return base
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + param + "=" + url.QueryEscape(payload)
}

// jsReflectionCheck returns a JS expression that reports whether a raw (unescaped)
// prefix of the payload appears in the live DOM.
func jsReflectionCheck(payload string) string {
	raw := payload
	if i := strings.IndexAny(raw, ">\"' "); i > 0 {
		raw = raw[:i]
	}
	if raw == "" {
		return "false"
	}
	b, _ := json.Marshal(raw)
	return `(function(){ try { return document.documentElement.outerHTML.indexOf(` + string(b) + `) !== -1; } catch(e) { return false; } })()`
}

func xssEvidence(r *XSSVerifyResult) string {
	var parts []string
	if r.DialogFired {
		parts = append(parts, fmt.Sprintf("alert dialog fired (message=%q)", r.DialogMessage))
	}
	if r.DOMMarker {
		parts = append(parts, "in-page JS marker window.__behemothXss was set by the payload")
	}
	if r.ReflectionRaw {
		parts = append(parts, "payload reflected unescaped in the live DOM")
	}
	if len(parts) == 0 {
		if r.Error != "" {
			return "no execution evidence; last error: " + r.Error
		}
		return "no execution evidence (no dialog, no DOM marker, no raw reflection)"
	}
	return strings.Join(parts, "; ")
}
