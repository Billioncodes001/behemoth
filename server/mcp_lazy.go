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
