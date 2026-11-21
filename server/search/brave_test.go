package search

import "testing"

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
