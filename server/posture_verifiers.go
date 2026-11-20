package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// ============================================================================
// 1. ASYNC WEBHOOK / CALLBACK RECEIPT VERIFIER
// ============================================================================

type callbackEventRecord struct {
	ReceivedAt  string            `json:"received_at"`
	Tag         string            `json:"tag"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	RemoteAddr  string            `json:"remote_addr"`
	ContentType string            `json:"content_type,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	BodyLength  int               `json:"body_length"`
	SafeHeaders map[string]string `json:"safe_headers,omitempty"`
}

type callbackListenerEntry struct {
	Token     string                `json:"token"`
	Label     string                `json:"label"`
	CreatedAt time.Time             `json:"created_at"`
	ExpiresAt time.Time             `json:"expires_at"`
	Events    []callbackEventRecord `json:"events"`
}

var (
	callbackMu        sync.Mutex
	callbackListeners = map[string]*callbackListenerEntry{}
)

// handleCallbackReceipt records inbound webhook / asynchronous verification
// callbacks sent to /api/oast-cb/{token}/{tag...}.
func (s *Server) handleCallbackReceipt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/api/oast-cb/")
	parts := strings.SplitN(trimmed, "/", 2)
	token := strings.TrimSpace(parts[0])
	tag := "default"
	if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
		tag = strings.TrimSpace(parts[1])
	}
	if token == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	safeHdrs := map[string]string{}
	for _, k := range []string{"X-Request-Id", "X-Forwarded-For", "Origin", "Referer"} {
		if v := strings.TrimSpace(r.Header.Get(k)); v != "" {
			if len(v) > 200 {
				v = v[:200]
			}
			safeHdrs[k] = v
		}
	}

	now := time.Now().UTC()
	callbackMu.Lock()
	entry, ok := callbackListeners[token]
	if ok && now.Before(entry.ExpiresAt) {
		if len(entry.Events) < 200 {
			entry.Events = append(entry.Events, callbackEventRecord{
				ReceivedAt:  now.Format(time.RFC3339Nano),
				Tag:         tag,
				Method:      r.Method,
				Path:        r.URL.Path,
				RemoteAddr:  getClientIP(r),
				ContentType: r.Header.Get("Content-Type"),
				UserAgent:   firstLine(r.UserAgent(), 160),
				BodyLength:  len(bodyBytes),
				SafeHeaders: safeHdrs,
			})
		}
	} else if ok {
		delete(callbackListeners, token)
		ok = false
	}
	callbackMu.Unlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"recorded"}`))
}

func (s *Server) toolCreateCallbackListener() actool.CoreTool {
	return wrTool("create_callback_listener",
		"Register a temporary correlation callback URL (/api/oast-cb/<token>/<tag>) to verify asynchronous webhook delivery or outbound egress filtering policies during authorized testing.",
		objSchema(map[string]any{
			"label":            strParam("Short label describing what webhook or async flow is being verified"),
			"public_base_url":  strParam("Optional externally reachable base URL of this ARTEX instance (e.g. https://console.example.com)"),
			"ttl_seconds":      map[string]any{"type": "integer", "description": "Listener lifetime in seconds (default 900, max 3600)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Label         string `json:"label"`
				PublicBaseURL string `json:"public_base_url"`
				TTLSeconds    int    `json:"ttl_seconds"`
			}
			_ = json.Unmarshal(in, &a)
			ttl := 900 * time.Second
			if a.TTLSeconds > 0 {
				if a.TTLSeconds > 3600 {
					a.TTLSeconds = 3600
				}
				ttl = time.Duration(a.TTLSeconds) * time.Second
			}
			now := time.Now().UTC()
			token := "cb_" + randomShortHex(10)
			entry := &callbackListenerEntry{
				Token:     token,
				Label:     strings.TrimSpace(a.Label),
				CreatedAt: now,
				ExpiresAt: now.Add(ttl),
			}
			callbackMu.Lock()
			for k, v := range callbackListeners {
				if now.After(v.ExpiresAt) {
					delete(callbackListeners, k)
				}
			}
			callbackListeners[token] = entry
			callbackMu.Unlock()

			base := strings.TrimRight(strings.TrimSpace(a.PublicBaseURL), "/")
			if base == "" {
				base = strings.TrimRight(strings.TrimSpace(os.Getenv("ARTEX_PUBLIC_URL")), "/")
			}
			relPath := fmt.Sprintf("/api/oast-cb/%s/verify", token)
			fullURL := relPath
			if base != "" {
				fullURL = base + relPath
			}
			return jsonResult(map[string]any{
				"token":         token,
				"callback_path": relPath,
				"callback_url":  fullURL,
				"expires_at":    entry.ExpiresAt.Format(time.RFC3339),
				"mitigation_guidance": []string{
					"Enforce strict outbound URL allowlists and block RFC1918/link-local/metadata IP ranges at the HTTP client dialer layer.",
					"Sign outbound webhooks with HMAC-SHA256 and validate TLS certificates on webhook consumers.",
				},
			})
		})
}

func (s *Server) toolPollCallbackEvents() actool.CoreTool {
	return roTool("poll_callback_events",
		"Inspect recorded asynchronous callback / webhook verification events for a token created by create_callback_listener.",
		objSchema(map[string]any{
			"token": strParam("Callback correlation token returned by create_callback_listener"),
			"clear": map[string]any{"type": "boolean", "description": "Optional: clear stored events after reading"},
		}, "token"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Token string `json:"token"`
				Clear bool   `json:"clear"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			token := strings.TrimSpace(a.Token)
			now := time.Now().UTC()
			callbackMu.Lock()
			entry, ok := callbackListeners[token]
			if !ok || now.After(entry.ExpiresAt) {
				delete(callbackListeners, token)
				callbackMu.Unlock()
				return jsonResult(map[string]any{"found": false, "events": []any{}, "count": 0})
			}
			eventsCopy := append([]callbackEventRecord(nil), entry.Events...)
			if a.Clear {
				entry.Events = nil
			}
			exp := entry.ExpiresAt.Format(time.RFC3339)
			lbl := entry.Label
			callbackMu.Unlock()

			return jsonResult(map[string]any{
				"found":      true,
				"token":      token,
				"label":      lbl,
				"expires_at": exp,
				"count":      len(eventsCopy),
				"events":     eventsCopy,
			})
		})
}

// ============================================================================
// 2. MULTI-ROLE ACCESS-CONTROL POLICY MATRIX VERIFIER
// ============================================================================

type authRoleSession struct {
	Role        string            `json:"role"`
	Description string            `json:"description,omitempty"`
	BearerToken string            `json:"-"`
	Cookie      string            `json:"-"`
	Headers     map[string]string `json:"headers,omitempty"`
	UpdatedAt   string            `json:"updated_at"`
}

var (
	authVaultMu sync.RWMutex
	authVault   = map[string]authRoleSession{}
)

func (s *Server) toolManageAuthSessions() actool.CoreTool {
	return wrTool("manage_auth_sessions",
		"Store, list, or clear named test-role authentication sessions (e.g. unauthenticated, user_a, user_b, admin) in memory for multi-role RBAC/ABAC access-control verification.",
		objSchema(map[string]any{
			"action":       strParam("Operation: set | list | delete | clear"),
			"role":         strParam("Role identifier (e.g. user_a, user_b, admin, auditor)"),
			"description":  strParam("Optional role description (e.g. Standard tenant-A member)"),
			"bearer_token": strParam("Optional Authorization Bearer token for this test role"),
			"cookie":       strParam("Optional Cookie header value for this test role"),
			"headers":      map[string]any{"type": "object", "description": "Optional custom HTTP headers (e.g. {\"X-API-Key\":\"...\"})"},
		}, "action"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Action      string            `json:"action"`
				Role        string            `json:"role"`
				Description string            `json:"description"`
				BearerToken string            `json:"bearer_token"`
				Cookie      string            `json:"cookie"`
				Headers     map[string]string `json:"headers"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			switch strings.ToLower(strings.TrimSpace(a.Action)) {
			case "set":
				role := strings.TrimSpace(a.Role)
				if role == "" {
					return actool.Errorf("role is required for action=set"), nil
				}
				authVaultMu.Lock()
				authVault[role] = authRoleSession{
					Role:        role,
					Description: strings.TrimSpace(a.Description),
					BearerToken: strings.TrimSpace(strings.TrimPrefix(a.BearerToken, "Bearer ")),
					Cookie:      strings.TrimSpace(a.Cookie),
					Headers:     a.Headers,
					UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
				}
				authVaultMu.Unlock()
				return jsonResult(map[string]any{"stored": true, "role": role})

			case "delete":
				role := strings.TrimSpace(a.Role)
				authVaultMu.Lock()
				delete(authVault, role)
				authVaultMu.Unlock()
				return jsonResult(map[string]any{"deleted": true, "role": role})

			case "clear":
				authVaultMu.Lock()
				authVault = map[string]authRoleSession{}
				authVaultMu.Unlock()
				return jsonResult(map[string]any{"cleared": true})

			case "list":
				authVaultMu.RLock()
				roles := make([]map[string]any, 0, len(authVault))
				for _, r := range authVault {
					roles = append(roles, map[string]any{
						"role":             r.Role,
						"description":      r.Description,
						"has_bearer_token": r.BearerToken != "",
						"has_cookie":       r.Cookie != "",
						"header_count":     len(r.Headers),
						"updated_at":       r.UpdatedAt,
					})
				}
				authVaultMu.RUnlock()
				sort.Slice(roles, func(i, j int) bool {
					return fmt.Sprint(roles[i]["role"]) < fmt.Sprint(roles[j]["role"])
				})
				return jsonResult(map[string]any{"roles": roles, "count": len(roles)})

			default:
				return actool.Errorf("unsupported action; choose set, list, delete, or clear"), nil
			}
		})
}

func (s *Server) toolVerifyAccessControlMatrix() actool.CoreTool {
	return wrTool("verify_access_control_matrix",
		"Evaluate an authorized API endpoint across stored test roles (plus an unauthenticated baseline) to verify RBAC/ABAC enforcement and identify broken object/function-level authorization discrepancies.",
		objSchema(map[string]any{
			"url":                     strParam("Authorized target endpoint URL to verify"),
			"method":                  strParam("HTTP method (default GET)"),
			"body":                    strParam("Optional JSON/form request body"),
			"content_type":            strParam("Optional Content-Type header (default application/json when body is set)"),
			"roles":                   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Role names from manage_auth_sessions to compare (defaults to all stored roles)"},
			"expected_authorized":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Roles that SHOULD be permitted to access this resource (used to flag unauthorized 2xx responses)"},
			"include_unauthenticated": map[string]any{"type": "boolean", "description": "Also test without credentials (default true)"},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL                    string   `json:"url"`
				Method                 string   `json:"method"`
				Body                   string   `json:"body"`
				ContentType            string   `json:"content_type"`
				Roles                  []string `json:"roles"`
				ExpectedAuthorized     []string `json:"expected_authorized"`
				IncludeUnauthenticated *bool    `json:"include_unauthenticated"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			targetURL := strings.TrimSpace(a.URL)
			if targetURL == "" {
				return actool.Errorf("url is required"), nil
			}
			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = http.MethodGet
			}
			incUnauth := true
			if a.IncludeUnauthenticated != nil {
				incUnauth = *a.IncludeUnauthenticated
			}

			authVaultMu.RLock()
			selected := make([]authRoleSession, 0)
			if len(a.Roles) == 0 {
				for _, rs := range authVault {
					selected = append(selected, rs)
				}
				sort.Slice(selected, func(i, j int) bool { return selected[i].Role < selected[j].Role })
			} else {
				for _, rn := range a.Roles {
					if rs, ok := authVault[strings.TrimSpace(rn)]; ok {
						selected = append(selected, rs)
					}
				}
			}
			authVaultMu.RUnlock()

			if incUnauth {
				selected = append([]authRoleSession{{Role: "unauthenticated", Description: "No credentials"}}, selected...)
			}
			expectedSet := map[string]bool{}
			for _, r := range a.ExpectedAuthorized {
				expectedSet[strings.TrimSpace(r)] = true
			}

			client := s.newProxyAwareHTTPClient(15*time.Second, false)
			matrix := make([]map[string]any, 0, len(selected))
			var discrepancies []map[string]any

			for _, rs := range selected {
				var bodyReader io.Reader
				if a.Body != "" {
					bodyReader = strings.NewReader(a.Body)
				}
				req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
				if err != nil {
					return actool.Errorf("build request: " + err.Error()), nil
				}
				if a.Body != "" {
					ct := strings.TrimSpace(a.ContentType)
					if ct == "" {
						ct = "application/json"
					}
					req.Header.Set("Content-Type", ct)
				}
				if rs.BearerToken != "" {
					req.Header.Set("Authorization", "Bearer "+rs.BearerToken)
				}
				if rs.Cookie != "" {
					req.Header.Set("Cookie", rs.Cookie)
				}
				for hk, hv := range rs.Headers {
					req.Header.Set(hk, hv)
				}

				resp, err := client.Do(req)
				if err != nil {
					matrix = append(matrix, map[string]any{
						"role":  rs.Role,
						"error": err.Error(),
					})
					continue
				}
				respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
				_ = resp.Body.Close()

				jsonKeys := extractTopLevelJSONKeys(respBytes)
				row := map[string]any{
					"role":           rs.Role,
					"status_code":    resp.StatusCode,
					"content_length": len(respBytes),
					"content_type":   resp.Header.Get("Content-Type"),
					"json_keys":      jsonKeys,
				}
				matrix = append(matrix, row)

				if len(expectedSet) > 0 && !expectedSet[rs.Role] && resp.StatusCode >= 200 && resp.StatusCode < 300 {
					discrepancies = append(discrepancies, map[string]any{
						"role":        rs.Role,
						"status_code": resp.StatusCode,
						"issue":       "Role not listed in expected_authorized received a 2xx response",
						"remediation": "Enforce server-side resource ownership and role policy checks before returning or mutating records.",
					})
				}
			}

			return jsonResult(map[string]any{
				"url":                  targetURL,
				"method":               method,
				"matrix":               matrix,
				"policy_discrepancies": discrepancies,
			})
		})
}

func extractTopLevelJSONKeys(b []byte) []string {
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(b), &m); err != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 25 {
		keys = keys[:25]
	}
	return keys
}

// ============================================================================
// 3. FRONTEND BUNDLE & API SURFACE POSTURE AUDITOR
// ============================================================================

var (
	scriptSrcRe   = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.m?js(?:\?[^"']*)?)["']`)
	apiRouteLitRe = regexp.MustCompile(`["'` + "`" + `](/(?:api|v[1-4]|graphql|trpc|rest|auth|oauth|admin|internal)/[A-Za-z0-9_\-./:{}]+)["'` + "`" + `]`)
	sdkConfigPatterns = []struct {
		Name        string
		Pattern     *regexp.Regexp
		Remediation string
	}{
		{
			Name:        "Supabase Service/Anon JWT Pattern",
			Pattern:     regexp.MustCompile(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}`),
			Remediation: "Ensure service_role JWTs are never bundled into frontend assets and verify Row-Level Security (RLS) policies on all exposed tables.",
		},
		{
			Name:        "Cloud Provider Access Key Prefix",
			Pattern:     regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
			Remediation: "Revoke long-lived IAM access keys in client bundles; replace with short-lived server-issued presigned URLs or federated credentials.",
		},
		{
			Name:        "Stripe Secret / Live Key Prefix",
			Pattern:     regexp.MustCompile(`\b(?:sk_live|rk_live)_[0-9a-zA-Z]{16,}\b`),
			Remediation: "Keep secret payment keys exclusively on backend servers; only publishable keys (pk_*) belong in browser code.",
		},
		{
			Name:        "SourceMap Reference",
			Pattern:     regexp.MustCompile(`//# sourceMappingURL=([^\s]+\.map)`),
			Remediation: "Disable public .map deployment in production builds and upload source maps privately to your error-monitoring service instead.",
		},
	}
)

func (s *Server) toolAuditFrontendAPISurface() actool.CoreTool {
	return roTool("audit_frontend_api_surface",
		"Audit an authorized web application's public HTML and JavaScript bundles to inventory referenced API routes, check source-map / GraphQL schema exposure, and flag accidentally embedded client secrets with redacted summaries.",
		objSchema(map[string]any{
			"url":         strParam("Authorized web application page URL (e.g. https://app.example.com)"),
			"max_bundles": map[string]any{"type": "integer", "description": "Maximum number of referenced JS bundles to inspect (default 8, max 20)"},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL        string `json:"url"`
				MaxBundles int    `json:"max_bundles"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			baseURL, err := url.Parse(strings.TrimSpace(a.URL))
			if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
				return actool.Errorf("valid absolute url is required"), nil
			}
			maxBundles := 8
			if a.MaxBundles > 0 {
				if a.MaxBundles > 20 {
					a.MaxBundles = 20
				}
				maxBundles = a.MaxBundles
			}

			client := s.newProxyAwareHTTPClient(15*time.Second, true)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), nil)
			if err != nil {
				return actool.Errorf("build request: " + err.Error()), nil
			}
			resp, err := client.Do(req)
			if err != nil {
				return actool.Errorf("fetch page failed: " + err.Error()), nil
			}
			htmlBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			_ = resp.Body.Close()
			htmlStr := string(htmlBytes)

			routeSet := map[string]bool{}
			for _, m := range apiRouteLitRe.FindAllStringSubmatch(htmlStr, 200) {
				routeSet[m[1]] = true
			}

			var bundleURLs []string
			seenBundles := map[string]bool{}
			for _, m := range scriptSrcRe.FindAllStringSubmatch(htmlStr, 50) {
				u, perr := baseURL.Parse(m[1])
				if perr != nil {
					continue
				}
				us := u.String()
				if !seenBundles[us] {
					seenBundles[us] = true
					bundleURLs = append(bundleURLs, us)
					if len(bundleURLs) >= maxBundles {
						break
					}
				}
			}

			var configFindings []map[string]any
			inspectedBundles := 0
			for _, bu := range bundleURLs {
				breq, berr := http.NewRequestWithContext(ctx, http.MethodGet, bu, nil)
				if berr != nil {
					continue
				}
				bresp, berr := client.Do(breq)
				if berr != nil {
					continue
				}
				jsBytes, _ := io.ReadAll(io.LimitReader(bresp.Body, 1024*1024))
				_ = bresp.Body.Close()
				if bresp.StatusCode != http.StatusOK {
					continue
				}
				inspectedBundles++
				jsStr := string(jsBytes)
				for _, m := range apiRouteLitRe.FindAllStringSubmatch(jsStr, 300) {
					routeSet[m[1]] = true
				}
				for _, pat := range sdkConfigPatterns {
					if match := pat.Pattern.FindString(jsStr); match != "" {
						configFindings = append(configFindings, map[string]any{
							"category":       pat.Name,
							"bundle_url":     bu,
							"redacted_match": redactSensitiveSample(match),
							"remediation":    pat.Remediation,
						})
					}
				}
			}

			routes := make([]string, 0, len(routeSet))
			for r := range routeSet {
				routes = append(routes, r)
			}
			sort.Strings(routes)
			if len(routes) > 150 {
				routes = routes[:150]
			}

			securityHeaders := map[string]bool{
				"content_security_policy":   resp.Header.Get("Content-Security-Policy") != "",
				"strict_transport_security": resp.Header.Get("Strict-Transport-Security") != "",
				"x_frame_options":           resp.Header.Get("X-Frame-Options") != "",
				"x_content_type_options":    resp.Header.Get("X-Content-Type-Options") != "",
			}

			return jsonResult(map[string]any{
				"url":                     baseURL.String(),
				"http_status":             resp.StatusCode,
				"bundles_discovered":      len(bundleURLs),
				"bundles_inspected":       inspectedBundles,
				"referenced_api_routes":   routes,
				"security_header_posture": securityHeaders,
				"bundle_posture_findings": configFindings,
			})
		})
}

func redactSensitiveSample(s string) string {
	if len(s) <= 10 {
		return s[:minInt(3, len(s))] + "***"
	}
	return s[:6] + "...[REDACTED]..." + s[len(s)-4:]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// 4. ENDPOINT IDEMPOTENCY & CONCURRENCY LOCK VERIFIER
// ============================================================================

func (s *Server) toolVerifyEndpointIdempotency() actool.CoreTool {
	return wrTool("verify_endpoint_idempotency",
		"Verify whether an authorized transactional API endpoint enforces idempotency keys, optimistic locking, or atomic database constraints under a small bounded batch (2-15) of simultaneous requests.",
		objSchema(map[string]any{
			"url":          strParam("Authorized endpoint URL to evaluate for idempotency"),
			"method":       strParam("HTTP method (default POST)"),
			"body":         strParam("Request payload (e.g. test idempotency transaction body)"),
			"content_type": strParam("Content-Type header (default application/json)"),
			"headers":      map[string]any{"type": "object", "description": "Optional auth/idempotency headers"},
			"concurrency":  map[string]any{"type": "integer", "description": "Bounded concurrent request count between 2 and 15 (default 5)"},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL         string            `json:"url"`
				Method      string            `json:"method"`
				Body        string            `json:"body"`
				ContentType string            `json:"content_type"`
				Headers     map[string]string `json:"headers"`
				Concurrency int               `json:"concurrency"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			targetURL := strings.TrimSpace(a.URL)
			if targetURL == "" {
				return actool.Errorf("url is required"), nil
			}
			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = http.MethodPost
			}
			n := a.Concurrency
			if n < 2 {
				n = 5
			}
			if n > 15 {
				n = 15 // Strictly bounded for safe QA verification
			}
			ct := strings.TrimSpace(a.ContentType)
			if ct == "" {
				ct = "application/json"
			}

			client := s.newProxyAwareHTTPClient(15*time.Second, false)
			type sample struct {
				Index      int   `json:"index"`
				StatusCode int   `json:"status_code"`
				DurationMs int64 `json:"duration_ms"`
				BodyLength int   `json:"body_length"`
				Err        string `json:"error,omitempty"`
			}
			results := make([]sample, n)
			ready := sync.WaitGroup{}
			done := sync.WaitGroup{}
			release := make(chan struct{})
			ready.Add(n)
			done.Add(n)

			for i := 0; i < n; i++ {
				go func(idx int) {
					defer done.Done()
					var br io.Reader
					if a.Body != "" {
						br = strings.NewReader(a.Body)
					}
					req, err := http.NewRequestWithContext(ctx, method, targetURL, br)
					if err != nil {
						ready.Done()
						results[idx] = sample{Index: idx, Err: err.Error()}
						return
					}
					if a.Body != "" {
						req.Header.Set("Content-Type", ct)
					}
					for hk, hv := range a.Headers {
						req.Header.Set(hk, hv)
					}
					ready.Done()
					<-release
					t0 := time.Now()
					resp, err := client.Do(req)
					dur := time.Since(t0).Milliseconds()
					if err != nil {
						results[idx] = sample{Index: idx, DurationMs: dur, Err: err.Error()}
						return
					}
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
					_ = resp.Body.Close()
					results[idx] = sample{
						Index:      idx,
						StatusCode: resp.StatusCode,
						DurationMs: dur,
						BodyLength: len(b),
					}
				}(i)
			}

			ready.Wait()
			close(release)
			done.Wait()

			statusDist := map[string]int{}
			success2xx := 0
			for _, r := range results {
				if r.StatusCode > 0 {
					key := fmt.Sprintf("%d", r.StatusCode)
					statusDist[key]++
					if r.StatusCode >= 200 && r.StatusCode < 300 {
						success2xx++
					}
				}
			}

			assessment := "Only <=1 request succeeded with 2xx or endpoint appears read-only / idempotent."
			if success2xx > 1 && (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete) {
				assessment = fmt.Sprintf("%d/%d concurrent state-changing requests returned 2xx; verify database state to confirm whether idempotency / row locking prevented duplicate side effects.", success2xx, n)
			}

			return jsonResult(map[string]any{
				"url":                 targetURL,
				"method":              method,
				"concurrency":         n,
				"status_distribution": statusDist,
				"success_2xx_count":   success2xx,
				"assessment":          assessment,
				"samples":             results,
				"remediation_guidance": []string{
					"Require an Idempotency-Key header backed by a unique constraint or distributed lock for non-idempotent state transitions.",
					"Use atomic conditional SQL updates (UPDATE ... WHERE balance >= $1 AND version = $2) or SELECT ... FOR UPDATE inside serializable/read-committed transactions.",
				},
			})
		})
}

// ============================================================================
// 5. STATIC SOURCE ROUTE & MIDDLEWARE SECURITY AUDITOR
// ============================================================================

var sourceRouteDetectors = []struct {
	Framework string
	Exts      []string
	RouteRe   *regexp.Regexp
	AuthHint  *regexp.Regexp
}{
	{
		Framework: "Express / Fastify / Hono (JS/TS)",
		Exts:      []string{".js", ".ts", ".mjs"},
		RouteRe:   regexp.MustCompile(`\b(?:app|router)\.(get|post|put|patch|delete|all)\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`),
		AuthHint:  regexp.MustCompile(`(?i)\b(auth|requireAuth|isAuthenticated|verifyToken|jwt|rbac|guard|protect|session)\b`),
	},
	{
		Framework: "FastAPI / Flask (Python)",
		Exts:      []string{".py"},
		RouteRe:   regexp.MustCompile(`@(?:app|router|bp|blueprint)\.(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]`),
		AuthHint:  regexp.MustCompile(`(?i)\b(Depends|login_required|jwt_required|current_user|require_auth|permission)\b`),
	},
	{
		Framework: "Go net/http / Gin / Echo",
		Exts:      []string{".go"},
		RouteRe:   regexp.MustCompile(`\b(?:mux\.HandleFunc|http\.HandleFunc|r\.(?:GET|POST|PUT|PATCH|DELETE)|e\.(?:GET|POST|PUT|PATCH|DELETE))\s*\(\s*"([^"]+)"`),
		AuthHint:  regexp.MustCompile(`(?i)\b(requireAuth|authMiddleware|jwt|Auth|Guard|Permission)\b`),
	},
}

func (s *Server) toolAuditSourceRoutes() actool.CoreTool {
	return roTool("audit_source_routes",
		"Perform static security posture analysis on a local codebase directory to inventory HTTP route definitions with file:line references and highlight routes lacking apparent authentication/authorization middleware.",
		objSchema(map[string]any{
			"source_dir": strParam("Local directory path inside the workspace containing source code to audit"),
			"max_routes": map[string]any{"type": "integer", "description": "Maximum routes to return (default 100, max 300)"},
		}, "source_dir"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				SourceDir string `json:"source_dir"`
				MaxRoutes int    `json:"max_routes"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			dir := filepath.Clean(strings.TrimSpace(a.SourceDir))
			st, err := os.Stat(dir)
			if err != nil || !st.IsDir() {
				return actool.Errorf("source_dir must be an existing directory"), nil
			}
			maxRoutes := 100
			if a.MaxRoutes > 0 {
				if a.MaxRoutes > 300 {
					a.MaxRoutes = 300
				}
				maxRoutes = a.MaxRoutes
			}

			type routeEntry struct {
				Framework       string `json:"framework"`
				File            string `json:"file"`
				Line            int    `json:"line"`
				Route           string `json:"route"`
				HasApparentAuth bool   `json:"has_apparent_auth"`
			}
			var discovered []routeEntry
			filesScanned := 0

			_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return nil
				}
				if d.IsDir() {
					name := d.Name()
					if name == ".git" || name == "node_modules" || name == "vendor" || name == ".next" || name == "dist" || name == "__pycache__" {
						return filepath.SkipDir
					}
					return nil
				}
				if len(discovered) >= maxRoutes || filesScanned >= 1500 {
					return filepath.SkipAll
				}
				ext := strings.ToLower(filepath.Ext(path))
				var matchedDetectors []int
				for idx, det := range sourceRouteDetectors {
					for _, e := range det.Exts {
						if ext == e {
							matchedDetectors = append(matchedDetectors, idx)
							break
						}
					}
				}
				if len(matchedDetectors) == 0 {
					return nil
				}
				info, ierr := d.Info()
				if ierr != nil || info.Size() > 512*1024 {
					return nil
				}
				contentBytes, rerr := os.ReadFile(path)
				if rerr != nil {
					return nil
				}
				filesScanned++
				lines := strings.Split(string(contentBytes), "\n")
				rel, relErr := filepath.Rel(dir, path)
				if relErr != nil {
					rel = path
				}

				for lineIdx, line := range lines {
					for _, detIdx := range matchedDetectors {
						det := sourceRouteDetectors[detIdx]
						m := det.RouteRe.FindStringSubmatch(line)
						if len(m) == 0 {
							continue
						}
						routeLabel := m[len(m)-1]
						if len(m) >= 3 {
							routeLabel = strings.ToUpper(m[1]) + " " + m[2]
						}
						// Inspect the route declaration line plus preceding decorator lines
						// and continuation lines up to (but never crossing into) an adjacent route.
						var windowLines []string
						for prev := lineIdx - 1; prev >= maxInt(0, lineIdx-3); prev-- {
							if det.RouteRe.MatchString(lines[prev]) || strings.TrimSpace(lines[prev]) == "" {
								break
							}
							windowLines = append(windowLines, lines[prev])
						}
						windowLines = append(windowLines, line)
						for next := lineIdx + 1; next < minInt(len(lines), lineIdx+4); next++ {
							if det.RouteRe.MatchString(lines[next]) {
								break
							}
							windowLines = append(windowLines, lines[next])
							if strings.Contains(lines[next-1], ";") {
								break
							}
						}
						windowText := strings.Join(windowLines, "\n")
						hasAuth := det.AuthHint.MatchString(windowText)
						discovered = append(discovered, routeEntry{
							Framework:       det.Framework,
							File:            rel,
							Line:            lineIdx + 1,
							Route:           routeLabel,
							HasApparentAuth: hasAuth,
						})
						if len(discovered) >= maxRoutes {
							return filepath.SkipAll
						}
					}
				}
				return nil
			})

			unprotectedCount := 0
			for _, r := range discovered {
				if !r.HasApparentAuth {
					unprotectedCount++
				}
			}

			return jsonResult(map[string]any{
				"source_dir":                   dir,
				"files_scanned":                filesScanned,
				"routes_count":                 len(discovered),
				"routes_missing_apparent_auth": unprotectedCount,
				"routes":                       discovered,
			})
		})
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
