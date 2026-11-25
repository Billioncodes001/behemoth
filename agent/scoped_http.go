package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// scopedHTTPTool is the agent's scope-enforced HTTP client. It exists because the
// SDK's WebFetch and Bash/curl bypass scope entirely — notably on redirects, where
// a 302 can walk the agent off the allowlist. Every request here is authorized
// before it leaves, every redirect hop is re-authorized and re-rate-limited, and
// each response body is hashed so the observation can be tied back to a byte-exact
// body later.
//
// Read-only and concurrency-safe: it never mutates server state beyond the
// request method the model explicitly asks for.

const (
	scopedHTTPDefaultTimeout = 30 * time.Second
	scopedHTTPMaxTimeout     = 120 * time.Second
	scopedHTTPDefaultBytes   = 262144  // 256 KiB excerpt by default
	scopedHTTPMaxBytes       = 2097152 // hard cap: 2 MiB
)

// ScopedHTTPTool builds the http_request tool bound to guard g. When g is nil the
// tool still works (unscoped tasks), it just enforces nothing.
func ScopedHTTPTool(g *ScopeGuard) actool.CoreTool {
	return ScopedHTTPToolWithProxy(g, nil, "")
}

// ScopedHTTPToolWithProxy builds the scope-enforced http_request tool and routes
// outbound requests through BEHEMOTH's live egress/recording proxy (Proxy Pool,
// Exclusive Tor, MITM Capture, or Fail-Closed guard) so target probes never leak
// the server's real IP or skip packet capture.
func ScopedHTTPToolWithProxy(g *ScopeGuard, resolveProxy func() string, caCert string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "http_request",
		Description: "Scope-enforced HTTP request. Authorizes the URL and every redirect hop against the task scope, " +
			"honors the per-host rate limit, and returns status, headers, a body excerpt and the body SHA-256. " +
			"Prefer this over curl/WebFetch when the task has an explicit scope: it is the only HTTP path that " +
			"cannot silently follow a redirect to an out-of-scope host.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":              str("Absolute http(s) URL to request."),
				"method":           str("HTTP method (default GET)."),
				"headers":          map[string]any{"type": "object", "description": "Optional request headers.", "additionalProperties": map[string]any{"type": "string"}},
				"body":             str("Optional request body (raw string)."),
				"timeout_seconds":  intp("Request timeout in seconds (default 30, max 120)."),
				"max_bytes":        intp("Body excerpt cap in bytes (default 262144, max 2097152)."),
				"follow_redirects": map[string]any{"type": "boolean", "description": "Follow redirects, re-authorizing each hop (default true)."},
			},
			"required": []string{"url"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var proxyURL string
			if resolveProxy != nil {
				proxyURL = strings.TrimSpace(resolveProxy())
			}
			effectiveCA := strings.TrimSpace(caCert)
			if tc != nil && len(tc.Env) > 0 {
				for _, kv := range tc.Env {
					if proxyURL == "" && (strings.HasPrefix(kv, "HTTP_PROXY=") || strings.HasPrefix(kv, "HTTPS_PROXY=") || strings.HasPrefix(kv, "ALL_PROXY=")) {
						_, v, _ := strings.Cut(kv, "=")
						proxyURL = strings.TrimSpace(v)
					}
					if effectiveCA == "" && strings.HasPrefix(kv, "SSL_CERT_FILE=") {
						_, v, _ := strings.Cut(kv, "=")
						effectiveCA = strings.TrimSpace(v)
					}
				}
			}
			return runScopedHTTP(ctx, g, in, proxyURL, effectiveCA), nil
		},
	})
}

func runScopedHTTP(ctx context.Context, g *ScopeGuard, in json.RawMessage, proxyURL, caCert string) actool.Result {
	var args struct {
		URL             string            `json:"url"`
		Method          string            `json:"method"`
		Headers         map[string]string `json:"headers"`
		Body            string            `json:"body"`
		TimeoutSeconds  int               `json:"timeout_seconds"`
		MaxBytes        int               `json:"max_bytes"`
		FollowRedirects *bool             `json:"follow_redirects"`
	}
	if err := json.Unmarshal(in, &args); err != nil {
		return actool.Errorf("invalid input: " + err.Error())
	}
	if strings.TrimSpace(args.URL) == "" {
		return actool.Errorf("url is required")
	}
	method := strings.ToUpper(strings.TrimSpace(args.Method))
	if method == "" {
		method = http.MethodGet
	}
	timeout := scopedHTTPDefaultTimeout
	if args.TimeoutSeconds > 0 {
		timeout = time.Duration(args.TimeoutSeconds) * time.Second
		if timeout > scopedHTTPMaxTimeout {
			timeout = scopedHTTPMaxTimeout
		}
	}
	maxBytes := args.MaxBytes
	if maxBytes <= 0 {
		maxBytes = scopedHTTPDefaultBytes
	}
	if maxBytes > scopedHTTPMaxBytes {
		maxBytes = scopedHTTPMaxBytes
	}

	decision, err := g.RequireURL(args.URL)
	if err != nil {
		if d, ok := err.(*ScopeViolation); ok {
			b, _ := json.Marshal(map[string]any{"decision": d, "error": err.Error()})
			return actool.Errorf(string(b))
		}
		return actool.Errorf(err.Error())
	}
	g.RateLimit(ctx, decision.Host)

	req, err := http.NewRequestWithContext(ctx, method, args.URL, strings.NewReader(args.Body))
	if err != nil {
		return actool.Errorf("build request: " + err.Error())
	}
	for k, v := range args.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "BEHEMOTH/scope-guard")
	}

	client := g.HTTPClientWithProxy(timeout, proxyURL, caCert)
	defer client.CloseIdleConnections()
	if args.FollowRedirects != nil && !*args.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		b, _ := json.Marshal(map[string]any{"url": args.URL, "error": err.Error(), "decision": decision})
		return actool.Errorf(string(b))
	}
	defer resp.Body.Close() //nolint:errcheck

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	truncated := len(raw) > maxBytes
	if truncated {
		raw = raw[:maxBytes]
	}
	sum := sha256.Sum256(raw)

	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[k] = strings.Join(resp.Header.Values(k), ", ")
	}
	out := map[string]any{
		"url":         args.URL,
		"final_url":   resp.Request.URL.String(),
		"method":      method,
		"status":      resp.StatusCode,
		"reason":      resp.Status,
		"headers":     headers,
		"body":        string(raw),
		"body_bytes":  len(raw),
		"body_sha256": hex.EncodeToString(sum[:]),
		"truncated":   truncated,
		"elapsed_ms":  time.Since(started).Milliseconds(),
		"decision":    decision,
	}
	if readErr != nil && !truncated {
		out["read_error"] = readErr.Error()
	}
	b, merr := json.Marshal(out)
	if merr != nil {
		return actool.Errorf(merr.Error())
	}
	return actool.Text(string(b))
}

// scopeHintForPrompt renders a one-line scope summary the worker system prompt can
// carry when a guard is active (empty when unscoped). Kept short: the model needs
// to know probing is enforced, not the whole rule table.
func scopeHintForPrompt(g *ScopeGuard) string {
	if g == nil || !g.ScopeEnabled() {
		return ""
	}
	sum := g.Summary()
	parts := []string{}
	if hosts, ok := sum["hosts"].([]string); ok && len(hosts) > 0 {
		parts = append(parts, "hosts: "+strings.Join(hosts, ", "))
	}
	if nets, ok := sum["networks"].([]string); ok && len(nets) > 0 {
		parts = append(parts, "networks: "+strings.Join(nets, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("\n\n[Scope Enforcement] Network probes are checked mechanically against this task's scope (%s). Requests and redirect hops to any other host are rejected, and per-host request rate is throttled. Use http_request for target HTTP calls so redirects stay inside scope.", strings.Join(parts, "; "))
}
