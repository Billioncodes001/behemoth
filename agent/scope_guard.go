package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/behemoth/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Scope enforcement. BEHEMOTH's scope lives in task_scope (root_domain / subdomain /
// ip / cidr rows) and is normally only expressed to the model as prompt text —
// nothing stops a probe at an out-of-scope host, and redirects silently leave the
// allowlist. This guard turns the same rows into a mechanical boundary for the
// agent's own network tools:
//
//   - authorize every URL/host before a request leaves the process (fail-closed:
//     an unresolvable host is denied rather than assumed in scope);
//   - re-authorize every redirect hop (a 302 to an external host is a new target);
//   - throttle per host with a token bucket so probes stay polite.
//
// It is a guardrail for the agent's HTTP tool + Bash command literals, not a
// network sandbox — the Docker sandbox (sandbox_exec) is the isolation boundary.

// ScopeViolation is returned when a target is outside the authorized scope.
type ScopeViolation struct {
	Reason string
	Target string
	Host   string
	Port   int
}

func (e *ScopeViolation) Error() string {
	if e.Target != "" && e.Target != e.Host {
		return fmt.Sprintf("scope violation: %s (%s)", e.Reason, e.Target)
	}
	return "scope violation: " + e.Reason
}

// ScopeDecision is the outcome of one authorization check (also logged into tool
// results so the model can see exactly what was refused and why).
type ScopeDecision struct {
	Allowed bool     `json:"allowed"`
	Reason  string   `json:"reason,omitempty"`
	Target  string   `json:"target,omitempty"`
	Host    string   `json:"host,omitempty"`
	Port    int      `json:"port,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

type scopeHostRule struct {
	host     string // lower-case, no leading "*." — the base domain
	port     int    // 0 = any port
	wildcard bool   // matches the base domain and every subdomain
}

func (r scopeHostRule) matches(host string, port int) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	base := strings.ToLower(strings.TrimSuffix(r.host, "."))
	if r.wildcard {
		if host != base && !strings.HasSuffix(host, "."+base) {
			return false
		}
	} else if host != base {
		return false
	}
	if r.port != 0 && port != 0 && r.port != port {
		return false
	}
	return true
}

type scopeURLRule struct {
	scheme     string
	host       scopeHostRule
	pathPrefix string
}

// ScopeGuard authorizes targets, re-authorizes redirects and rate-limits per
// host. A zero-target guard is "unscoped": every check passes (tasks without
// explicit scope rows behave exactly as before).
type ScopeGuard struct {
	mu       sync.Mutex
	hosts    []scopeHostRule
	urls     []scopeURLRule
	nets     []*net.IPNet
	denyHost []scopeHostRule
	denyNets []*net.IPNet

	allowPrivate  bool
	allowLoopback bool
	maxRPS        float64
	next          map[string]time.Time // token-bucket bookkeeping per host
	resolve       func(host string) []string
}

var (
	scopeURLRe   = regexp.MustCompile(`(?i)https?://[^\s"'<>|;]+`)
	scopeIPv4Re  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	encodedPctRe = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

// ScopePatternsFromTaskScopes converts task_scope rows into guard patterns:
// root_domain → wildcard (apex + subdomains), subdomain → exact host,
// ip → exact host, cidr → network. keyword/company rows carry no host shape and
// are skipped (asset rows still land in task_scope as subdomain/ip).
func ScopePatternsFromTaskScopes(scopes []db.TaskScope) []string {
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		switch sc.Kind {
		case "root_domain":
			v := strings.TrimSpace(sc.Domain)
			if v == "" {
				v = strings.TrimSpace(sc.Value)
			}
			if v != "" {
				out = append(out, "*."+strings.TrimPrefix(strings.TrimPrefix(v, "*."), "."))
			}
		case "subdomain":
			v := strings.TrimSpace(sc.Value)
			if v == "" {
				v = strings.TrimSpace(sc.Domain)
			}
			if v != "" {
				out = append(out, v)
			}
		case "ip":
			if v := strings.TrimSpace(sc.Value); v != "" {
				out = append(out, v)
			}
		case "cidr":
			v := strings.TrimSpace(sc.Net)
			if v == "" {
				v = strings.TrimSpace(sc.Value)
			}
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// NewScopeGuard builds a guard from patterns:
//
//	example.com          exact host, any port
//	*.example.com        base domain + all subdomains, any port
//	example.com:8443     exact host + port
//	10.10.0.0/24         CIDR
//	https://app.example.test/api   URL prefix (scheme+host+port+path)
//
// maxRPS ≤ 0 disables throttling. deny patterns are the same language and always
// win. No patterns = unscoped guard (all checks pass).
func NewScopeGuard(patterns, deny []string, maxRPS float64) *ScopeGuard {
	g := &ScopeGuard{
		allowPrivate:  true, // internal pentest targets are the common case
		allowLoopback: true,
		maxRPS:        maxRPS,
		next:          map[string]time.Time{},
		resolve:       defaultScopeResolve,
	}
	for _, p := range patterns {
		g.addPattern(p, false)
	}
	for _, p := range deny {
		g.addPattern(p, true)
	}
	return g
}

// SetResolver overrides DNS resolution (tests). nil restores the default.
func (g *ScopeGuard) SetResolver(fn func(string) []string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.resolve = fn
	g.mu.Unlock()
}

// ScopeEnabled reports whether any positive rule exists. Unscoped guards pass
// every check.
func (g *ScopeGuard) ScopeEnabled() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.hosts) > 0 || len(g.urls) > 0 || len(g.nets) > 0
}

// addPattern classifies one pattern into a host, URL or network rule.
func (g *ScopeGuard) addPattern(pattern string, deny bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return
	}
	if strings.Contains(pattern, "://") {
		u, err := url.Parse(pattern)
		if err != nil || u.Hostname() == "" {
			return
		}
		scheme := strings.ToLower(u.Scheme)
		port := u.Port()
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		portNum, _ := strconv.Atoi(port)
		host := strings.ToLower(u.Hostname())
		rule := scopeHostRule{host: strings.TrimPrefix(host, "*."), port: portNum,
			wildcard: strings.HasPrefix(host, "*.")}
		g.mu.Lock()
		if deny {
			g.denyHost = append(g.denyHost, rule)
		} else {
			g.urls = append(g.urls, scopeURLRule{scheme: scheme, host: rule,
				pathPrefix: strings.TrimSuffix(u.Path, "/")})
		}
		g.mu.Unlock()
		return
	}
	if _, ipnet, err := net.ParseCIDR(pattern); err == nil {
		g.mu.Lock()
		if deny {
			g.denyNets = append(g.denyNets, ipnet)
		} else {
			g.nets = append(g.nets, ipnet)
		}
		g.mu.Unlock()
		return
	}
	host, port := splitScopeHostPort(pattern)
	if host == "" {
		return
	}
	rule := scopeHostRule{host: strings.TrimPrefix(strings.ToLower(host), "*."), port: port,
		wildcard: strings.HasPrefix(host, "*.")}
	g.mu.Lock()
	if deny {
		g.denyHost = append(g.denyHost, rule)
	} else {
		g.hosts = append(g.hosts, rule)
	}
	g.mu.Unlock()
}

// splitScopeHostPort separates "host:port" / "[v6]:port" without touching IPv6
// literals that carry no port.
func splitScopeHostPort(pattern string) (string, int) {
	pattern = strings.TrimSpace(pattern)
	if strings.HasPrefix(pattern, "[") {
		if end := strings.Index(pattern, "]"); end != -1 {
			host := pattern[1:end]
			rest := pattern[end+1:]
			if strings.HasPrefix(rest, ":") {
				if p, err := strconv.Atoi(rest[1:]); err == nil {
					return host, p
				}
			}
			return host, 0
		}
		return pattern, 0
	}
	if strings.Count(pattern, ":") == 1 {
		host, portText, _ := strings.Cut(pattern, ":")
		if p, err := strconv.Atoi(portText); err == nil {
			return host, p
		}
	}
	return pattern, 0
}

// AuthorizeHost checks host:port against the guard. Unscoped guards allow all.
// host may be a domain, IPv4 or IPv6 literal. Resolution failure is fail-closed
// when a scope is configured.
func (g *ScopeGuard) AuthorizeHost(host string, port int) ScopeDecision {
	if g == nil {
		return ScopeDecision{Allowed: true, Host: host, Port: port}
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ScopeDecision{Reason: "empty target host"}
	}
	g.mu.Lock()
	unscoped := len(g.hosts) == 0 && len(g.urls) == 0 && len(g.nets) == 0
	denyHosts := append([]scopeHostRule(nil), g.denyHost...)
	denyNets := append([]*net.IPNet(nil), g.denyNets...)
	hosts := append([]scopeHostRule(nil), g.hosts...)
	urls := append([]scopeURLRule(nil), g.urls...)
	nets := append([]*net.IPNet(nil), g.nets...)
	resolve := g.resolve
	allowPrivate, allowLoopback := g.allowPrivate, g.allowLoopback
	g.mu.Unlock()

	if !unscoped {
		for _, rule := range denyHosts {
			if rule.matches(host, port) {
				return ScopeDecision{Reason: "host matches deny rule '" + rule.host + "'", Host: host, Port: port}
			}
		}
	}

	// Resolve to IPs. Literal IPs skip DNS. An empty result under a scope is a
	// deny: we cannot prove the host is authorized.
	ips := []string{}
	if ip := net.ParseIP(host); ip != nil {
		ips = []string{ip.String()}
	} else if resolve != nil {
		ips = resolve(host)
	}
	if unscoped {
		return ScopeDecision{Allowed: true, Reason: "in scope (no scope configured)", Host: host, Port: port, IPs: ips}
	}
	if len(ips) == 0 {
		return ScopeDecision{Reason: "cannot resolve host '" + host + "' — denied (fail-closed DNS)", Host: host, Port: port}
	}

	for _, ipText := range ips {
		ip := net.ParseIP(ipText)
		if ip == nil {
			continue
		}
		for _, deny := range denyNets {
			if deny.Contains(ip) {
				return ScopeDecision{Reason: "address " + ipText + " matches deny network " + deny.String(), Host: host, Port: port, IPs: ips}
			}
		}
		if ip.IsLoopback() && !allowLoopback {
			return ScopeDecision{Reason: "loopback address " + ipText + " not allowed", Host: host, Port: port, IPs: ips}
		}
		if ip.IsPrivate() && !allowPrivate && !ip.IsLoopback() {
			return ScopeDecision{Reason: "private address " + ipText + " not allowed", Host: host, Port: port, IPs: ips}
		}
		if allowLoopback && (ip.IsLoopback() || ip.IsUnspecified()) {
			// 127.0.0.1 / ::1 / 0.0.0.0 are the agent's own host (recording proxy,
			// locally started listeners), not engagement targets: never scope-checked.
			return ScopeDecision{Allowed: true, Reason: "local address", Host: host, Port: port, IPs: ips}
		}
	}

	for _, rule := range hosts {
		if rule.matches(host, port) {
			return ScopeDecision{Allowed: true, Reason: "in scope", Host: host, Port: port, IPs: ips}
		}
	}
	for _, rule := range urls {
		if rule.host.matches(host, port) {
			return ScopeDecision{Allowed: true, Reason: "in scope (URL rule)", Host: host, Port: port, IPs: ips}
		}
	}
	for _, network := range nets {
		for _, ipText := range ips {
			if ip := net.ParseIP(ipText); ip != nil && network.Contains(ip) {
				return ScopeDecision{Allowed: true, Reason: "in scope (" + network.String() + ")", Host: host, Port: port, IPs: ips}
			}
		}
	}
	return ScopeDecision{Reason: "target is not in scope", Host: host, Port: port, IPs: ips}
}

// AuthorizeURL checks a full http(s) URL, including path-prefix URL rules.
func (g *ScopeGuard) AuthorizeURL(raw string) ScopeDecision {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ScopeDecision{Reason: "empty URL"}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ScopeDecision{Reason: "unparseable URL: " + err.Error(), Target: raw}
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ScopeDecision{Reason: "unsupported scheme '" + u.Scheme + "' (http/https only)", Target: raw}
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	if port == 0 {
		port = 80
		if scheme == "https" {
			port = 443
		}
	}
	decision := g.AuthorizeHost(u.Hostname(), port)
	decision.Target = raw
	if !decision.Allowed {
		return decision
	}
	path, ok, reason := validateScopedPath(u.Path)
	if !ok {
		decision.Allowed = false
		decision.Reason = reason
		return decision
	}
	if g != nil {
		g.mu.Lock()
		rules := append([]scopeURLRule(nil), g.urls...)
		g.mu.Unlock()
		host := strings.ToLower(u.Hostname())
		for _, rule := range rules {
			if rule.pathPrefix == "" || !rule.host.matches(host, port) {
				continue
			}
			if path != rule.pathPrefix && !strings.HasPrefix(path, rule.pathPrefix+"/") {
				decision.Allowed = false
				decision.Reason = "path '" + path + "' is outside the authorized prefix '" + rule.pathPrefix + "'"
				return decision
			}
			decision.Reason = "in scope (URL prefix)"
		}
	}
	return decision
}

// validateScopedPath rejects control characters, ambiguous separators and dot
// traversal segments (including percent-encoded ones) without rewriting the path.
func validateScopedPath(rawPath string) (string, bool, string) {
	path := rawPath
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return path, false, "URL path must start with '/'"
	}
	for _, ch := range path {
		if ch < 0x20 || ch == 0x7f {
			return path, false, "URL path contains control characters"
		}
	}
	if strings.Contains(path, "\\") || strings.Contains(path, "//") {
		return path, false, "URL path contains an ambiguous separator"
	}
	cur := path
	for i := 0; i < 5; i++ {
		for _, seg := range strings.Split(cur, "/") {
			if seg == "." || seg == ".." {
				return path, false, "URL path contains dot traversal segments"
			}
		}
		if !encodedPctRe.MatchString(cur) {
			break
		}
		decoded, err := url.PathUnescape(cur)
		if err != nil {
			return path, false, "URL path contains malformed percent-encoding"
		}
		if decoded == cur {
			break
		}
		if strings.Contains(decoded, "\\") || strings.Contains(decoded, "//") {
			return path, false, "decoded URL path contains an ambiguous separator"
		}
		cur = decoded
	}
	if decoded, err := url.PathUnescape(cur); err == nil {
		for _, seg := range strings.Split(decoded, "/") {
			if seg == "." || seg == ".." {
				return path, false, "URL path contains dot traversal segments"
			}
		}
	}
	normalized := strings.TrimSuffix(path, "/")
	if normalized == "" {
		normalized = "/"
	}
	return normalized, true, ""
}

// RequireURL is AuthorizeURL returning a *ScopeViolation error when denied.
func (g *ScopeGuard) RequireURL(raw string) (ScopeDecision, error) {
	d := g.AuthorizeURL(raw)
	if !d.Allowed {
		return d, &ScopeViolation{Reason: d.Reason, Target: raw, Host: d.Host, Port: d.Port}
	}
	return d, nil
}

// RequireHost is AuthorizeHost returning a *ScopeViolation error when denied.
func (g *ScopeGuard) RequireHost(host string, port int) (ScopeDecision, error) {
	d := g.AuthorizeHost(host, port)
	if !d.Allowed {
		return d, &ScopeViolation{Reason: d.Reason, Target: host, Host: d.Host, Port: d.Port}
	}
	return d, nil
}

// ---------- rate limiting ----------

// RateLimit blocks until the per-host token bucket allows the next request. A
// guard with maxRPS ≤ 0 never blocks. ctx cancellation aborts the wait.
func (g *ScopeGuard) RateLimit(ctx context.Context, host string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	rps := g.maxRPS
	if rps <= 0 {
		g.mu.Unlock()
		return
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	interval := time.Duration(float64(time.Second) / rps)
	now := time.Now()
	nextAt := g.next[host]
	if nextAt.Before(now) {
		nextAt = now
	}
	g.next[host] = nextAt.Add(interval)
	wait := nextAt.Sub(now)
	g.mu.Unlock()
	if wait <= 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// ---------- shell command heuristic ----------

// CheckCommand scans a shell command for literal URLs and IPv4 addresses and
// authorizes each. It is a guardrail for the common "nmap 8.8.8.8" mistake, not a
// sandbox: only explicit literals are checked.
func (g *ScopeGuard) CheckCommand(command string) ScopeDecision {
	if g == nil || strings.TrimSpace(command) == "" {
		return ScopeDecision{Allowed: true}
	}
	for _, raw := range scopeURLRe.FindAllString(command, -1) {
		if d := g.AuthorizeURL(strings.TrimRight(raw, ".,);")); !d.Allowed {
			return d
		}
	}
	for _, literal := range scopeIPv4Re.FindAllString(command, -1) {
		ip := net.ParseIP(literal)
		if ip == nil || ip.To4() == nil {
			continue
		}
		if d := g.AuthorizeHost(literal, 0); !d.Allowed {
			return d
		}
	}
	return ScopeDecision{Allowed: true, Reason: "no out-of-scope literal found"}
}

// ---------- HTTP client with redirect re-authorization ----------

// HTTPClient returns a client that re-authorizes (and re-rate-limits) every
// redirect hop. A 302 to an out-of-scope host fails the request instead of
// silently leaving the allowlist.
func (g *ScopeGuard) HTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if g == nil {
				return nil
			}
			d, err := g.RequireURL(req.URL.String())
			if err != nil {
				return fmt.Errorf("redirect to %s denied: %s", req.URL.String(), d.Reason)
			}
			g.RateLimit(req.Context(), req.URL.Hostname())
			return nil
		},
	}
}

// ---------- defaults ----------

// defaultScopeResolve resolves a host to its addresses with a short timeout. An
// error yields an empty slice (fail-closed at the caller).
func defaultScopeResolve(host string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	seen := map[string]bool{}
	for _, a := range addrs {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// ScopeRPSFromEnv returns the per-host request rate for scope enforcement. Zero
// (the default) disables throttling; BEHEMOTH_SCOPE_RPS overrides.
func ScopeRPSFromEnv() float64 {
	if v := strings.TrimSpace(os.Getenv("BEHEMOTH_SCOPE_RPS")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
	}
	return 0
}

// NewTaskScopeGuard builds a guard from a task's scope rows. Returns nil when the
// task has no scope rows — unscoped tasks keep the prior unguarded behavior.
func NewTaskScopeGuard(as *db.AssetStore, taskID int64) *ScopeGuard {
	if as == nil || taskID <= 0 {
		return nil
	}
	scopes, err := as.ListTaskScope(taskID)
	if err != nil {
		return nil
	}
	patterns := ScopePatternsFromTaskScopes(scopes)
	if len(patterns) == 0 {
		return nil
	}
	return NewScopeGuard(patterns, nil, ScopeRPSFromEnv())
}

// Summary renders the guard's rules for prompts, tool output and tests.
func (g *ScopeGuard) Summary() map[string]any {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	hosts := make([]string, 0, len(g.hosts))
	for _, r := range g.hosts {
		label := r.host
		if r.wildcard {
			label = "*." + label
		}
		if r.port != 0 {
			label += ":" + strconv.Itoa(r.port)
		}
		hosts = append(hosts, label)
	}
	nets := make([]string, 0, len(g.nets))
	for _, n := range g.nets {
		nets = append(nets, n.String())
	}
	urls := make([]string, 0, len(g.urls))
	for _, r := range g.urls {
		urls = append(urls, r.scheme+"://"+r.host.host+r.pathPrefix)
	}
	return map[string]any{
		"hosts":     hosts,
		"networks":  nets,
		"url_rules": urls,
		"max_rps":   g.maxRPS,
		"enabled":   len(g.hosts) > 0 || len(g.urls) > 0 || len(g.nets) > 0,
	}
}

// ---------- tool wrapping ----------

// scopeGuardedTool authorizes target-facing tool inputs before execution.
// Bash commands are scanned for literal URLs/IPs; WebFetch URLs are authorized
// outright. Denials come back as tool errors so the model can adapt.
type scopeGuardedTool struct {
	actool.CoreTool
	guard *ScopeGuard
}

func (t *scopeGuardedTool) AcceptsRawInput() bool {
	if ra, ok := t.CoreTool.(rawInputAcceptor); ok {
		return ra.AcceptsRawInput()
	}
	return false
}

func (t *scopeGuardedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if d := t.authorize(ctx, in); !d.Allowed {
		return actool.Errorf(fmt.Sprintf("out of scope: %s — %s is not covered by this task's scope (see task_scope). Only authorized targets may be probed.", d.Reason, firstNonEmpty(d.Target, d.Host))), nil
	}
	return t.CoreTool.Call(ctx, in, tc)
}

// authorize extracts the target-bearing field for the tool and checks it.
func (t *scopeGuardedTool) authorize(ctx context.Context, in json.RawMessage) ScopeDecision {
	switch t.Name() {
	case "Bash":
		var args struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(in, &args); err != nil {
			return ScopeDecision{Allowed: true}
		}
		return t.guard.CheckCommand(args.Command)
	case "WebFetch":
		var args struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(in, &args); err != nil || strings.TrimSpace(args.URL) == "" {
			return ScopeDecision{Allowed: true}
		}
		d := t.guard.AuthorizeURL(args.URL)
		if d.Allowed {
			t.guard.RateLimit(ctx, d.Host)
		}
		return d
	}
	return ScopeDecision{Allowed: true}
}

// wrapScopeGuardTools applies the guard to the target-facing tools in the list.
// Other tools pass through untouched. nil guard → tools unchanged.
func wrapScopeGuardTools(tools []actool.CoreTool, g *ScopeGuard) []actool.CoreTool {
	if g == nil || len(tools) == 0 {
		return tools
	}
	out := make([]actool.CoreTool, len(tools))
	for i, t := range tools {
		switch t.Name() {
		case "Bash", "WebFetch":
			out[i] = &scopeGuardedTool{CoreTool: t, guard: g}
		default:
			out[i] = t
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
