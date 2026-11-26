package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Autumn-27/behemoth/db"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// lazyMCPConnection defers spawning STDIO/HTTP MCP servers (`npx`, `python3`) until
// an agent actually searches for a tool's schema (SearchExtraTools) or invokes a tool
// (ExecuteExtraTool) on that server. Because MCP tools in BEHEMOTH are deferred by
// default and their names + descriptions are already cached in PostgreSQL
// (mcp_tools_cache), turns that do not invoke an MCP tool avoid 3–8 seconds of
// Node/Python subprocess cold-start latency completely!
type lazyMCPConnection struct {
	server  *db.MCPServer
	proxyFn func() string

	mu    sync.Mutex
	cl    mcpClient
	tools map[string]actool.CoreTool
}

func newLazyMCPConnection(m *db.MCPServer, proxyFn func() string) *lazyMCPConnection {
	return &lazyMCPConnection{
		server:  m,
		proxyFn: proxyFn,
	}
}

func (l *lazyMCPConnection) ensureTools(ctx context.Context) (map[string]actool.CoreTool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tools != nil {
		return l.tools, nil
	}
	var px string
	if l.proxyFn != nil {
		px = l.proxyFn()
	}
	dialCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cl, err := connectMCP(dialCtx, l.server, px)
	if err != nil {
		return nil, err
	}
	ts, err := cl.Tools(dialCtx)
	if err != nil {
		_ = cl.Close()
		return nil, err
	}
	byName := make(map[string]actool.CoreTool, len(ts))
	for _, t := range ts {
		byName[t.Name()] = t
	}
	l.cl = cl
	l.tools = byName
	return l.tools, nil
}

func (l *lazyMCPConnection) Close() error {
	l.mu.Lock()
	cl := l.cl
	l.cl = nil
	l.tools = nil
	l.mu.Unlock()
	if cl != nil {
		return cl.Close()
	}
	return nil
}

type lazyMCPTool struct {
	name string
	desc string
	conn *lazyMCPConnection
}

var _ actool.CoreTool = (*lazyMCPTool)(nil)

func (t *lazyMCPTool) Name() string        { return t.name }
func (t *lazyMCPTool) Description() string { return t.desc }
func (t *lazyMCPTool) Prompt() string      { return "" }

func (t *lazyMCPTool) InputSchema() map[string]any {
	tools, err := t.conn.ensureTools(context.Background())
	if err == nil {
		if realTool, ok := tools[t.name]; ok {
			return realTool.InputSchema()
		}
	}
	return map[string]any{"type": "object", "properties": map[string]any{}}
}

func (t *lazyMCPTool) IsReadOnly(in json.RawMessage) bool {
	return false
}

func (t *lazyMCPTool) IsConcurrencySafe(in json.RawMessage) bool {
	return true
}

func (t *lazyMCPTool) CheckPermissions(_ context.Context, _ json.RawMessage, _ acperm.Context) acperm.Decision {
	return acperm.Allowed()
}

func (t *lazyMCPTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	tools, err := t.conn.ensureTools(ctx)
	if err != nil {
		return actool.Errorf(fmt.Sprintf("MCP server %s connection failed: %v", t.conn.server.Name, err)), nil
	}
	realTool, ok := tools[t.name]
	if !ok {
		return actool.Errorf(fmt.Sprintf("MCP tool %s not found on server %s", t.name, t.conn.server.Name)), nil
	}
	return realTool.Call(ctx, in, tc)
}

var (
	mcpFailCooldownMu sync.Mutex
	mcpFailCooldown   = map[int64]time.Time{}
)

func shouldSkipFailedMCPConnect(serverID int64) bool {
	mcpFailCooldownMu.Lock()
	defer mcpFailCooldownMu.Unlock()
	until, ok := mcpFailCooldown[serverID]
	return ok && time.Now().Before(until)
}

func noteFailedMCPConnect(serverID int64) {
	mcpFailCooldownMu.Lock()
	mcpFailCooldown[serverID] = time.Now().Add(60 * time.Second)
	mcpFailCooldownMu.Unlock()
}

// defaultBuiltinMCPToolStubs returns pre-known tool metadata for built-in MCP
// servers so even brand-new databases (before background npx discovery finishes)
// assemble turns in <2ms via lazyMCPConnection with zero cold subprocess spawns.
func defaultBuiltinMCPToolStubs(serverName string) []db.MCPTool {
	switch serverName {
	case "browser":
		return []db.MCPTool{
			{Name: "mcp__browser__browser_navigate", Description: "Navigate headless Chromium to a URL"},
			{Name: "mcp__browser__browser_snapshot", Description: "Capture accessibility snapshot of the current page"},
			{Name: "mcp__browser__browser_click", Description: "Click an element on the web page"},
			{Name: "mcp__browser__browser_type", Description: "Type text into an editable element"},
			{Name: "mcp__browser__browser_evaluate", Description: "Evaluate JavaScript expression on page or element"},
			{Name: "mcp__browser__browser_take_screenshot", Description: "Take a screenshot of the current page"},
			{Name: "mcp__browser__browser_network_requests", Description: "List all network requests since page load"},
			{Name: "mcp__browser__browser_console_messages", Description: "Return all browser console messages"},
		}
	case "vuln_intel":
		return []db.MCPTool{
			{Name: "mcp__vuln_intel__cve_nvd_lookup", Description: "Fetch CVE details, CVSS vector, CWEs, and references from NIST NVD 2.0"},
			{Name: "mcp__vuln_intel__epss_exploit_probability", Description: "Query FIRST.org EPSS exploitation probability score"},
			{Name: "mcp__vuln_intel__cisa_kev_check", Description: "Check CISA Known Exploited Vulnerabilities catalog"},
			{Name: "mcp__vuln_intel__osv_package_vulns", Description: "Query OSV.dev vulnerabilities for an ecosystem package & version"},
		}
	case "recon_osint":
		return []db.MCPTool{
			{Name: "mcp__recon_osint__crtsh_subdomains", Description: "Enumerate subdomains via Certificate Transparency logs (crt.sh)"},
			{Name: "mcp__recon_osint__wayback_historical_urls", Description: "Discover historical endpoints via Internet Archive CDX API"},
			{Name: "mcp__recon_osint__security_txt_contacts", Description: "Retrieve /.well-known/security.txt disclosure contacts"},
		}
	case "web_sec_analyzer":
		return []db.MCPTool{
			{Name: "mcp__web_sec_analyzer__http_security_headers_audit", Description: "Audit HTTP security headers, cookies, and CORS configuration"},
			{Name: "mcp__web_sec_analyzer__jwt_decode_and_audit", Description: "Decode and audit JWT header, claims, and algorithm weaknesses"},
		}
	case "sequential_thinking":
		return []db.MCPTool{
			{Name: "mcp__sequential_thinking__sequentialthinking", Description: "Structured multi-step exploit chain and hypothesis reasoning"},
		}
	case "knowledge_memory":
		return []db.MCPTool{
			{Name: "mcp__knowledge_memory__create_entities", Description: "Create entities in persistent knowledge graph"},
			{Name: "mcp__knowledge_memory__search_nodes", Description: "Search nodes in persistent knowledge graph"},
			{Name: "mcp__knowledge_memory__read_graph", Description: "Read persistent knowledge graph"},
		}
	default:
		return nil
	}
}
