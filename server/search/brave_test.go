package search

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBraveEngine_AvailabilityAndIdentity(t *testing.T) {
	e := NewBraveSearchEngine("", true)
	if e.IsAvailable() {
		t.Error("engine must be unavailable without an API key")
	}
	if e.Engine() != EngineBrave {
		t.Errorf("Engine() = %q, want %q", e.Engine(), EngineBrave)
	}
	e2 := NewBraveSearchEngine("key", true)
	if !e2.IsAvailable() {
		t.Error("engine with key should be available")
	}
}

func TestClampMaxResults(t *testing.T) {
	if clampMaxResults(0, 20) != 10 {
		t.Error("zero should default to 10")
	}
	if clampMaxResults(50, 20) != 20 {
		t.Error("should clamp to max")
	}
	if clampMaxResults(5, 20) != 5 {
		t.Error("in-range values pass through")
	}
}

func TestBraveRegisteredWhenConfigured(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Brave.APIKey = "test-key"
	cfg.Brave.Enabled = true
	o := NewOrchestrator(cfg)
	found := false
	for _, eng := range o.GetAvailableEngines() {
		if eng == EngineBrave {
			found = true
		}
	}
	if !found {
		t.Errorf("brave engine should be registered and available, got %v", o.GetAvailableEngines())
	}
}

func TestBraveChainFallbacksIncludeBrave(t *testing.T) {
	o := NewOrchestrator(DefaultConfig())
	for _, mode := range []SearchMode{ModeGeneral, ModeNews, ModeExploit, ModeTechnical, ModeOSINT} {
		found := false
		for _, e := range o.fallbackChains[mode] {
			if e == EngineBrave {
				found = true
			}
		}
		if !found {
			t.Errorf("mode %s fallback chain missing brave", mode)
		}
	}
}

func TestUpdateEngineBrave(t *testing.T) {
	o := NewOrchestrator(DefaultConfig())
	o.UpdateEngine("brave", "abc")
	if !o.config.Brave.Enabled || o.config.Brave.APIKey != "abc" {
		t.Fatalf("brave config not updated: %+v", o.config.Brave)
	}
	if _, ok := o.engines[EngineBrave]; !ok {
		t.Error("brave engine should be registered after UpdateEngine")
	}
	o.UpdateEngine("brave", "")
	if _, ok := o.engines[EngineBrave]; ok {
		t.Error("brave engine should be deregistered when key cleared")
	}
}

func TestReadResponseBytesGunzipsRawGzipPayload(t *testing.T) {
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, _ = zw.Write([]byte(`{"web":{"results":[{"title":"CVE-2024-1234","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-1234","description":"Critical RCE"}]}}`))
	_ = zw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	decoded, err := readResponseBytes(resp, 2<<20)
	if err != nil {
		t.Fatalf("readResponseBytes failed: %v", err)
	}
	var br braveResponse
	if len(decoded) == 0 || decoded[0] == 0x1f {
		t.Fatalf("expected gunzipped JSON, got bytes=%x", decoded)
	}
	_ = br
}

func TestSearXNGAndLoopbackBypassExternalProxy(t *testing.T) {
	// Point outbound proxy to a guaranteed-dead port so any proxied request fails.
	SetProxyProvider(func() string { return "http://127.0.0.1:1" })
	defer SetProxyProvider(nil)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "127.0.0.1" {
			t.Errorf("expected X-Forwarded-For=127.0.0.1, got %q", r.Header.Get("X-Forwarded-For"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"title":"Advisory","url":"https://example.org/cve","content":"PoC details","engine":"github"}]}`))
	}))
	defer srv.Close()

	sx := NewSearXNGSearchEngine(srv.URL, true)
	res, err := sx.Handle(context.Background(), Request{Query: "cve-2024", Mode: ModeExploit, MaxResults: 3})
	if err != nil {
		t.Fatalf("local SearXNG failed when external proxy was set: %v", err)
	}
	if len(res.Results) != 1 || res.Results[0].Engine != "searxng:github" {
		t.Fatalf("unexpected SearXNG results: %+v", res.Results)
	}
}
