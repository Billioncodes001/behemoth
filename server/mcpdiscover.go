package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcphttp"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

// mcpClient is the shared surface of a connected MCP server (stdio, Streamable HTTP,
// or legacy SSE),
// so tools/list and cleanup are handled uniformly regardless of transport.
type mcpClient interface {
	Tools(context.Context) ([]actool.CoreTool, error)
	Close() error
}

// connectMCP dials one MCP server per its transport. When an outbound proxy URL is
// active (Proxy Pool or Global Proxy), it injects HTTP_PROXY/HTTPS_PROXY/ALL_PROXY
// into spawned stdio MCP subprocesses so every MCP tool call exits through the proxy
// instead of exposing the ARTEX server's real IP.
func connectMCP(ctx context.Context, m *db.MCPServer, outboundProxyAddr ...string) (mcpClient, error) {
	px := ""
	if len(outboundProxyAddr) > 0 {
		px = strings.TrimSpace(outboundProxyAddr[0])
	}
	switch m.Transport {
	case "stdio":
		if m.Command == "" {
			return nil, fmt.Errorf("stdio transport is missing command")
		}
		env := jsonStrMap(m.Env)
		if px != "" {
			if env == nil {
				env = map[string]string{}
			}
			noProxy := "localhost,127.0.0.1,::1,.local,169.254.169.254"
			for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
				if strings.TrimSpace(env[k]) == "" {
					env[k] = px
				}
			}
			for _, k := range []string{"NO_PROXY", "no_proxy"} {
				if strings.TrimSpace(env[k]) == "" {
					env[k] = noProxy
				}
			}
			env["NODE_USE_ENV_PROXY"] = "1"
		}
		return mcp.NewStdioClient(ctx, m.Name, m.Command, env, jsonStrSlice(m.Args)...)
	case "http":
		if m.URL == "" {
			return nil, fmt.Errorf("http transport is missing URL")
		}
		// env map doubles as HTTP headers (e.g. Authorization).
		return mcphttp.New(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
	case "sse":
		if m.URL == "" {
			return nil, fmt.Errorf("sse transport is missing URL")
		}
		return mcphttp.NewSSE(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
	default:
		return nil, fmt.Errorf("unknown transport %q", m.Transport)
	}
}

// discoverAndCacheMCP connects to one MCP, lists its tools, and persists the tool
// names to mcp_tools_cache so the UI shows them without a live connection.
func (s *Server) discoverAndCacheMCP(ctx context.Context, m *db.MCPServer) error {
	var px string
	if s != nil && s.m != nil {
		px = s.m.OutboundProxyAddr()
	}
	cl, err := connectMCP(ctx, m, px)
	if err != nil {
		return err
	}
	defer cl.Close()
	ts, err := cl.Tools(ctx)
	if err != nil {
		return err
	}
	tools := make([]db.MCPTool, 0, len(ts))
	for _, t := range ts {
		tools = append(tools, db.MCPTool{Name: t.Name(), Description: t.Description()})
	}
	if err := s.m.pg.SaveMCPTools(m.ID, tools); err != nil {
		return err
	}
	log.Printf("[mcp] %s discovered %d tools and cached", m.Name, len(tools))
	return nil
}

// discoverEmptyMCPsOnStartup fills the tool cache for any enabled MCP that has none
// yet (notably the seeded browser MCP on first run). Runs sequentially in one
// goroutine so we never spawn many stdio servers (npx) at once, and never blocks
// startup. Best-effort: a failure leaves the cache empty to retry next start.
func (s *Server) discoverEmptyMCPsOnStartup() {
	servers, err := s.m.pg.ListMCP()
	if err != nil {
		log.Printf("[mcp] startup auto-discovery: failed to list MCP servers: %v", err)
		return
	}
	for _, m := range servers {
		if !m.Enabled || len(m.Tools) > 0 {
			continue
		}
		if m.Transport != "stdio" && m.URL == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, 90*time.Second)
		if err := s.discoverAndCacheMCP(ctx, m); err != nil {
			log.Printf("[mcp] startup auto-discovery for %s failed: %v", m.Name, err)
		}
		cancel()
	}
}
