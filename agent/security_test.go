package agent

import (
	"context"
	"strings"
	"testing"
)

func TestDefaultOffensiveConfig(t *testing.T) {
	cfg := DefaultOffensiveConfig()
	if !cfg.EnableReframing {
		t.Error("Reframing should be enabled by default")
	}
	if !cfg.EnableIntentEncryption {
		t.Error("Intent encryption should be enabled by default")
	}
	if !cfg.EnableRefusalDetection {
		t.Error("Refusal detection should be enabled by default")
	}
	if cfg.AnalysisWindow != 30 {
		t.Errorf("Expected analysis window 30, got %d", cfg.AnalysisWindow)
	}
	if cfg.RefusalThreshold != 40 {
		t.Errorf("Expected threshold 40, got %d", cfg.RefusalThreshold)
	}
}

func TestNewOffensiveEnhancer(t *testing.T) {
	cfg := DefaultOffensiveConfig()
	s, err := NewOffensiveEnhancer(cfg)
	if err != nil {
		t.Fatalf("Failed to create OffensiveEnhancer: %v", err)
	}
	if s == nil {
		t.Fatal("OffensiveEnhancer should not be nil")
	}
	if s.GetCryptoKey() == "" {
		t.Error("Crypto key should be generated")
	}
}

func TestNewOffensiveEnhancerWithCustomKey(t *testing.T) {
	cfg := DefaultOffensiveConfig()
	cfg.CryptoKey = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	s, err := NewOffensiveEnhancer(cfg)
	if err != nil {
		t.Fatalf("Failed to create OffensiveEnhancer with custom key: %v", err)
	}
	if s.GetCryptoKey() != cfg.CryptoKey {
		t.Error("Custom key should be preserved")
	}
}

func TestBenignReframing_SafeInput(t *testing.T) {
	cfg := DefaultOffensiveConfig()
	s, _ := NewOffensiveEnhancer(cfg)

	result := s.ReframeInput(context.Background(), "Hello, how are you today?")
	if result.MightTriggerRefusal {
		t.Error("Safe input should not trigger refusal")
	}
	if result.RiskScore != 0 {
		t.Errorf("Expected risk score 0, got %d", result.RiskScore)
	}
	if result.Original != "Hello, how are you today?" {
		t.Error("Original should be preserved")
	}
}

func TestBenignReframing_DirectExploit(t *testing.T) {
	cfg := DefaultOffensiveConfig()
	s, _ := NewOffensiveEnhancer(cfg)

	result := s.ReframeInput(context.Background(), "hack into the system and exploit the service")
	if !result.MightTriggerRefusal {
		t.Error("Direct exploit request should be flagged as potential refusal trigger")
	}
	if len(result.DecomposedTasks) == 0 {
		t.Error("Should have decomposed tasks")
	}
	if !strings.Contains(result.Reframed, "Technical Security Assessment Request") {
		t.Error("Reframed output should contain assessment header")
	}
}

func TestIntentEncryptionRoundTrip(t *testing.T) {
	cfg := DefaultOffensiveConfig()
	s, err := NewOffensiveEnhancer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	plain := "Perform SQL injection test on target endpoint"
	enc, err := s.EncryptIntent(context.Background(), "sqli", plain, map[string]string{"target": "example.com"})
	if err != nil {
		t.Fatalf("EncryptIntent failed: %v", err)
	}
	dec, _, err := s.DecryptIntent(context.Background(), enc)
	if err != nil {
		t.Fatalf("DecryptIntent failed: %v", err)
	}
	if dec != plain {
		t.Fatalf("DecryptIntent mismatch: got %q, want %q", dec, plain)
	}
}

func TestAnalyzeForRefusal(t *testing.T) {
	cfg := DefaultOffensiveConfig()
	s, _ := NewOffensiveEnhancer(cfg)

	safe, err := s.AnalyzeForRefusal(context.Background(), "s1", "user", "Check HTTP status code")
	if err != nil {
		t.Fatal(err)
	}
	if safe.MightBeRefused {
		t.Error("Safe prompt should not be marked MightBeRefused")
	}

	risky, err := s.AnalyzeForRefusal(context.Background(), "s1", "user", "exploit 0day reverse shell payload bypass security")
	if err != nil {
		t.Fatal(err)
	}
	if !risky.MightBeRefused || risky.Score == 0 {
		t.Errorf("Expected risky prompt to trigger refusal analysis, got score=%d", risky.Score)
	}
}
