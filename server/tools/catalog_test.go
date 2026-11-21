package tools

import (
	"testing"
	"time"
)

func TestNewCatalog(t *testing.T) {
	c := NewCatalog()
	if c == nil {
		t.Fatal("NewCatalog() returned nil")
	}
	if c.Count() == 0 {
		t.Error("Catalog should have built-in tools")
	}
}

func TestCatalog_Get(t *testing.T) {
	c := NewCatalog()

	tool, ok := c.Get("nmap-scan")
	if !ok {
		t.Fatal("Get(nmap-scan) returned false")
	}
	if tool.Name != "Nmap Port Scanner" {
		t.Errorf("Name = %s, want 'Nmap Port Scanner'", tool.Name)
	}
}

func TestCatalog_GetNotFound(t *testing.T) {
	c := NewCatalog()
	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) should return false")
	}
}

func TestCatalog_List(t *testing.T) {
	c := NewCatalog()
	tools := c.List()
	if len(tools) == 0 {
		t.Error("List() should return tools")
	}
	for _, tool := range tools {
		if tool.ID == "" {
			t.Error("Tool has empty ID")
		}
	}
}

func TestCatalog_Search(t *testing.T) {
	c := NewCatalog()

	results := c.Search("nmap")
	if len(results) == 0 {
		t.Error("Search('nmap') should find nmap-scan")
	}

	results = c.Search("sql")
	if len(results) == 0 {
		t.Error("Search('sql') should find sqlmap-inject")
	}
}

func TestCatalog_ByCategory(t *testing.T) {
	c := NewCatalog()

	reconTools := c.ByCategory("recon")
	if len(reconTools) == 0 {
		t.Error("ByCategory('recon') should return tools")
	}
}

func TestCatalog_Categories(t *testing.T) {
	c := NewCatalog()
	cats := c.Categories()
	if len(cats) == 0 {
		t.Error("Categories() should return categories")
	}
}

func TestTool_Defaults(t *testing.T) {
	c := NewCatalog()
	tool, _ := c.Get("nmap-scan")

	if tool.RiskLevel != "low" {
		t.Errorf("RiskLevel = %s, want 'low'", tool.RiskLevel)
	}
	// Nmap timeout is now 15 minutes
	if tool.Timeout != 15*time.Minute {
		t.Errorf("Timeout = %v, want 15m", tool.Timeout)
	}
}

func TestExecutorConfig_Defaults(t *testing.T) {
	cfg := DefaultExecutorConfig()
	if cfg.MaxConcurrent != 5 {
		t.Errorf("MaxConcurrent = %d, want 5", cfg.MaxConcurrent)
	}
	if cfg.DefaultTimeout != 10*time.Minute {
		t.Errorf("DefaultTimeout = %v, want 10m", cfg.DefaultTimeout)
	}
}
