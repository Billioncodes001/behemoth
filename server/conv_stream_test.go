package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
)

func TestConvStreamHubPublishesDeltaAndActivity(t *testing.T) {
	ch, unsub := globalConvStreamHub.subscribe(9991)
	defer unsub()

	globalConvStreamHub.publish(9991, "delta", map[string]any{"kind": "text", "text": "Streaming token"})
	select {
	case frame := <-ch:
		if frame.Event != "delta" || !strings.Contains(string(frame.Data), "Streaming token") {
			t.Fatalf("unexpected SSE frame: %+v %s", frame, string(frame.Data))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for live SSE delta frame")
	}
}

func TestLazyMCPToolZeroSubprocessColdStart(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v)", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer pg.Close()

	// Create a stdio MCP server pointing to a non-existent binary, pre-seeded with cached tools.
	// If ToolAugment tried to cold-spawn the process at turn start, it would fail and return 0 tools!
	// With lazyMCPConnection, ToolAugment succeeds in <5ms with 0 subprocesses spawned!
	srvID, err := pg.SaveMCP(&db.MCPServer{
		Name:      "lazy_fast_test_mcp",
		Transport: "stdio",
		Command:   "/nonexistent/never-spawned-on-turn-start",
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("SaveMCP: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteMCP(srvID) })

	if err := pg.SaveMCPTools(srvID, []db.MCPTool{
		{Name: "mcp__lazy_fast_test_mcp__instant_probe", Description: "Instant cached MCP tool"},
	}); err != nil {
		t.Fatalf("SaveMCPTools: %v", err)
	}

	ag, err := pg.GetAgentByKey("auto")
	if err != nil || ag == nil {
		t.Fatalf("GetAgentByKey(auto): %v", err)
	}
	_ = pg.ToggleVisibility(ag.ID, "mcp", srvID, true)
	t.Cleanup(func() { _ = pg.ToggleVisibility(ag.ID, "mcp", srvID, false) })

	skillDir := t.TempDir()
	wireAgentAugment(pg, skillDir, nil)
	t.Cleanup(func() { agent.ToolAugment = nil })

	t0 := time.Now()
	extra, def, cleanup := agent.ToolAugment(context.Background(), "auto")
	defer cleanup()
	elapsed := time.Since(t0)

	foundLazy := false
	for _, tl := range extra {
		if tl.Name() == "mcp__lazy_fast_test_mcp__instant_probe" {
			foundLazy = true
			break
		}
	}
	if !foundLazy {
		t.Fatalf("expected lazy MCP tool registered from cache without spawning process; deferred=%v", def.Deferred)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected near-zero MCP assembly time, took %s", elapsed)
	}
}
