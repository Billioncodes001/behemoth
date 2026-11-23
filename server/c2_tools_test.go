package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newC2TestServer builds a bare server with only what the C2 tools need.
func newC2TestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{dataDir: t.TempDir()}
}

func callC2Tool(t *testing.T, s *Server, name string, args string) map[string]any {
	t.Helper()
	var found bool
	for _, tl := range s.c2Tools() {
		if tl.Name() != name {
			continue
		}
		found = true
		res, err := tl.Call(context.Background(), json.RawMessage(args), nil)
		if err != nil {
			t.Fatalf("%s call: %v", name, err)
		}
		if len(res.Content) == 0 {
			t.Fatalf("%s: empty result", name)
		}
		text := res.Content[0].Text
		if strings.HasPrefix(text, "Error:") {
			t.Fatalf("%s returned error: %s", name, text)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("%s: non-JSON result %q: %v", name, text, err)
		}
		return out
	}
	if !found {
		t.Fatalf("tool %s not registered", name)
	}
	return nil
}

func TestC2ToolSetRegistered(t *testing.T) {
	s := newC2TestServer(t)
	want := map[string]bool{
		"c2_build_implant": false, "c2_deploy": false, "c2_agents": false,
		"c2_task": false, "c2_results": false, "c2_kill": false,
	}
	for _, tl := range s.c2Tools() {
		if _, ok := want[tl.Name()]; ok {
			want[tl.Name()] = true
		}
		if tl.Description() == "" {
			t.Errorf("%s: empty description", tl.Name())
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %s missing from c2Tools()", name)
		}
	}
}

func TestC2BuildAgentsTaskKillFlow(t *testing.T) {
	s := newC2TestServer(t)
	t.Setenv("ARTEX_C2_PUBLIC_URL", "https://c2.example.test")

	out := callC2Tool(t, s, "c2_build_implant", `{"label":"unit","runtime":"bash","beacon_path":"assets/logo.png","resp_path":"assets/logo.bin","sleep_seconds":45}`)
	imRaw, ok := out["implant"].(map[string]any)
	if !ok {
		t.Fatalf("implant missing: %v", out)
	}
	id, _ := imRaw["id"].(string)
	if id == "" {
		t.Fatalf("implant id missing: %v", imRaw)
	}
	buildDir, _ := out["build_dir"].(string)
	if _, err := os.Stat(filepath.Join(buildDir, "implant.sh")); err != nil {
		t.Fatalf("implant artifact: %v", err)
	}
	script, err := os.ReadFile(filepath.Join(buildDir, "implant.sh"))
	if err != nil {
		t.Fatalf("read implant: %v", err)
	}
	if !containsAll(string(script), id, "assets/logo.png", "https://c2.example.test") {
		t.Fatalf("generated script missing expected values")
	}

	agents := callC2Tool(t, s, "c2_agents", `{}`)
	if n, _ := agents["count"].(float64); n != 1 {
		t.Fatalf("agent count: %v", agents["count"])
	}

	taskOut := callC2Tool(t, s, "c2_task", `{"implant_id":"`+id+`","command":"id"}`)
	task, _ := taskOut["task"].(map[string]any)
	if task == nil || task["status"] != "pending" {
		t.Fatalf("queued task: %v", taskOut)
	}

	// Simulate the implant checking in and returning output.
	mgr := s.c2Manager()
	if mgr == nil {
		t.Fatal("c2 manager nil")
	}
	got, ok := mgr.Dequeue(id)
	if !ok {
		t.Fatal("task not queued")
	}
	mgr.AddResult(id, got.ID, "uid=0(root)", "", 0)
	res := callC2Tool(t, s, "c2_results", `{"implant_id":"`+id+`","limit":5}`)
	results, _ := res["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results: %v", res)
	}
	first, _ := results[0].(map[string]any)
	if first["output"] != "uid=0(root)" {
		t.Fatalf("result output: %v", first)
	}

	killOut := callC2Tool(t, s, "c2_kill", `{"implant_id":"`+id+`"}`)
	killTask, _ := killOut["task"].(map[string]any)
	if killTask == nil || killTask["cmd"] != "kill" {
		t.Fatalf("kill task: %v", killOut)
	}
	im, _ := mgr.Get(id)
	if im.Status() != "killed" {
		t.Fatalf("implant status after kill: %s", im.Status())
	}
}

func TestC2ToolErrors(t *testing.T) {
	s := newC2TestServer(t)
	if out := callC2Tool(t, s, "c2_results", `{"limit":3}`); out["results"] == nil {
		t.Fatalf("empty results should still return a list: %v", out)
	}
	for _, tl := range s.c2Tools() {
		if tl.Name() != "c2_task" {
			continue
		}
		res, err := tl.Call(context.Background(), json.RawMessage(`{"implant_id":"c2_nope","command":"id"}`), nil)
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if len(res.Content) == 0 {
			t.Fatal("empty error result")
		}
		if !strings.Contains(res.Content[0].Text, "unknown implant") {
			t.Fatalf("unexpected error text: %s", res.Content[0].Text)
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if sub == "" || !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
