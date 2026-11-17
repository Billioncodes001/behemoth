package fingerprint

import (
	"testing"
)

func TestGetTLSSpec(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected string
	}{
		{"Chrome", "chrome_120", "Chrome 120"},
		{"Firefox", "firefox_120", "Firefox 120"},
		{"Safari", "safari_17", "Safari 17"},
		{"Unknown returns default", "unknown_id", "Chrome 120"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := GetTLSSpec(tt.id)
			if spec.Name != tt.expected {
				t.Errorf("GetTLSSpec(%s) = %s, want %s", tt.id, spec.Name, tt.expected)
			}
		})
	}
}

func TestGetAllTLSSpecs(t *testing.T) {
	specs := GetAllTLSSpecs()
	if len(specs) == 0 {
		t.Fatal("GetAllTLSSpecs() returned empty")
	}
	
	// Verify all specs have required fields
	for _, spec := range specs {
		if spec.ID == "" {
			t.Error("Spec has empty ID")
		}
		if spec.Name == "" {
			t.Error("Spec has empty Name")
		}
	}
}

func TestRandomTLSSpec(t *testing.T) {
	// Call multiple times to ensure we get valid specs
	for i := 0; i < 10; i++ {
		spec := RandomTLSSpec()
		if spec.ID == "" {
			t.Errorf("RandomTLSSpec() returned empty spec on iteration %d", i)
		}
	}
}

func TestNewTLSHTTPClient(t *testing.T) {
	spec := GetTLSSpec("chrome_120")
	client := NewTLSHTTPClient(spec)
	if client == nil {
		t.Fatal("NewTLSHTTPClient returned nil")
	}
	if client.Timeout != 30e9 { // 30 seconds in nanoseconds
		t.Errorf("Timeout = %v, want 30s", client.Timeout)
	}
}