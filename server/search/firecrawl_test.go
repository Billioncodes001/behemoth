package search

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveFirecrawl spins up a test double exposing both the v2 and v1 search
// endpoints so the fallback and response-shape handling can be verified.
func serveFirecrawl(t *testing.T, v2Status, v1Status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer fc-test-key" {
			t.Errorf("expected bearer auth header, got %q", got)
		}
		switch r.URL.Path {
		case "/v2/search":
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			w.WriteHeader(v2Status)
			_, _ = w.Write([]byte(`{"success":true,"data":{"web":[
				{"title":"Exploit DB","url":"https://www.exploit-db.com/cves","description":"CVE database"},
				{"title":"NVD","url":"https://nvd.nist.gov","description":"National Vulnerability Database"}
			],"news":[{"title":"HN","url":"https://news.ycombinator.com","description":"hacker news"}]}}`))
		case "/v1/search":
			w.WriteHeader(v1Status)
			_, _ = w.Write([]byte(`{"success":true,"data":[
				{"title":"Legacy v1 result","url":"https://example.com/v1","description":"from v1 endpoint"}
			]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestFirecrawlParseV2Response(t *testing.T) {
	srv := serveFirecrawl(t, http.StatusOK, http.StatusOK)
	defer srv.Close()

	eng := NewFirecrawlSearchEngine("fc-test-key", srv.URL, true)
	if !eng.IsAvailable() {
		t.Fatal("engine should be available with base URL set")
	}
	resp, err := eng.Handle(context.Background(), Request{Query: "cve-2024", MaxResults: 10})
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if resp.Engine != EngineFirecrawl {
		t.Fatalf("unexpected engine: %s", resp.Engine)
	}
	// web results come first, then news
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 results (2 web + 1 news), got %d", len(resp.Results))
	}
	if resp.Results[0].URL != "https://www.exploit-db.com/cves" || resp.Results[0].Title != "Exploit DB" {
		t.Fatalf("unexpected first result: %+v", resp.Results[0])
	}
	if resp.Results[2].URL != "https://news.ycombinator.com" {
		t.Fatalf("unexpected news result: %+v", resp.Results[2])
	}
}

func TestFirecrawlFallsBackToV1(t *testing.T) {
	srv := serveFirecrawl(t, http.StatusNotFound, http.StatusOK)
	defer srv.Close()

	eng := NewFirecrawlSearchEngine("fc-test-key", srv.URL, true)
	resp, err := eng.Handle(context.Background(), Request{Query: "sql injection", MaxResults: 5})
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].URL != "https://example.com/v1" {
		t.Fatalf("expected v1 fallback result, got %+v", resp.Results)
	}
}

func TestFirecrawlNoAPIKeySelfHosted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("self-hosted mode must not send an Authorization header")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{"web":[{"title":"t","url":"https://a.b","description":"d"}]}}`))
	}))
	defer srv.Close()

	eng := NewFirecrawlSearchEngine("", srv.URL, true)
	resp, err := eng.Handle(context.Background(), Request{Query: "q", MaxResults: 3})
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
}

func TestFirecrawlSiteFilterAndLimit(t *testing.T) {
	var seenLimit float64
	var seenDomains []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		if !strings.Contains(string(body), `"limit":3`) {
			t.Errorf("expected limit=3 in request body, got %s", body)
		}
		seenLimit = 3
		if strings.Contains(string(body), `"includeDomains":["target.com"]`) {
			seenDomains = []string{"target.com"}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{"web":[]}}`))
	}))
	defer srv.Close()

	eng := NewFirecrawlSearchEngine("", srv.URL, true)
	_, _ = eng.Handle(context.Background(), Request{Query: "q", MaxResults: 3, SiteFilter: "target.com"})
	if seenLimit != 3 || len(seenDomains) != 1 {
		t.Fatalf("site filter/limit not applied (limit=%v domains=%v)", seenLimit, seenDomains)
	}
}

func TestOrchestratorFirecrawlConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Firecrawl.BaseURL = "http://127.0.0.1:1" // unreachable, but registered
	cfg.Firecrawl.Enabled = true
	orch := NewOrchestrator(cfg)
	if !containsEngine(orch.GetAvailableEngines(), EngineFirecrawl) {
		t.Fatal("firecrawl engine should be registered with a base URL and no API key")
	}

	// UpdateEngine: bare base URL enables the engine; empty value disables it.
	orch.UpdateEngine("firecrawl", "")
	if containsEngine(orch.GetAvailableEngines(), EngineFirecrawl) {
		t.Fatal("firecrawl should be unregistered after clearing config")
	}
	orch.UpdateEngine("firecrawl", "http://127.0.0.1:1")
	if !containsEngine(orch.GetAvailableEngines(), EngineFirecrawl) {
		t.Fatal("firecrawl should be registered from a bare base URL")
	}
}

func containsEngine(list []SearchEngineType, want SearchEngineType) bool {
	for _, e := range list {
		if e == want {
			return true
		}
	}
	return false
}
