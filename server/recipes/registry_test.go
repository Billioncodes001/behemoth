package recipes

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecipeRegistry_Load(t *testing.T) {
	tmpDir := t.TempDir()
	
	recipeJSON := `{
		"id": "test-recipe",
		"name": "Test Recipe",
		"description": "A test recipe",
		"category": "test",
		"version": "1.0.0",
		"author": "test",
		"tags": ["test", "unit"],
		"command": "echo {target}",
		"parameters": [{"name": "target", "type": "string", "required": true, "description": "Target"}],
		"risk_level": "low",
		"requires": [],
		"examples": []
	}`
	
	if err := os.WriteFile(filepath.Join(tmpDir, "test.json"), []byte(recipeJSON), 0644); err != nil {
		t.Fatal(err)
	}

	baseReg := NewRecipeRegistry("")
	if err := baseReg.Load(); err != nil {
		t.Fatalf("base Load() error = %v", err)
	}
	builtinCount := baseReg.Count()

	reg := NewRecipeRegistry(tmpDir)
	if err := reg.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if reg.Count() != builtinCount+1 {
		t.Errorf("Count() = %d, want %d", reg.Count(), builtinCount+1)
	}
}

func TestRecipeRegistry_Get(t *testing.T) {
	tmpDir := t.TempDir()
	
	recipeJSON := `{
		"id": "get-test",
		"name": "Get Test",
		"description": "Test get",
		"category": "test",
		"version": "1.0.0",
		"author": "test",
		"tags": [],
		"parameters": [],
		"risk_level": "low",
		"requires": [],
		"examples": []
	}`
	os.WriteFile(filepath.Join(tmpDir, "get-test.json"), []byte(recipeJSON), 0644)

	reg := NewRecipeRegistry(tmpDir)
	reg.Load()

	recipe, ok := reg.Get("get-test")
	if !ok {
		t.Fatal("Get() returned false for existing recipe")
	}
	if recipe.Name != "Get Test" {
		t.Errorf("Name = %s, want 'Get Test'", recipe.Name)
	}
}

func TestRecipeRegistry_GetNotFound(t *testing.T) {
	reg := NewRecipeRegistry(t.TempDir())
	reg.Load()
	
	_, ok := reg.Get("nonexistent")
	if ok {
		t.Error("Get() returned true for non-existent recipe")
	}
}

func TestRecipeRegistry_Search(t *testing.T) {
	tmpDir := t.TempDir()
	
	r1 := `{"id": "nmap-scan", "name": "Nmap Port Scanner", "description": "Port scanning tool", "category": "recon", "version": "1.0.0", "author": "test", "tags": ["network", "scan"], "parameters": [], "risk_level": "low", "requires": [], "examples": []}`
	r2 := `{"id": "sqlmap-inject", "name": "SQLMap Injection", "description": "SQL injection testing", "category": "exploit", "version": "1.0.0", "author": "test", "tags": ["sqli", "database"], "parameters": [], "risk_level": "high", "requires": [], "examples": []}`
	
	os.WriteFile(filepath.Join(tmpDir, "nmap-scan.json"), []byte(r1), 0644)
	os.WriteFile(filepath.Join(tmpDir, "sqlmap-inject.json"), []byte(r2), 0644)

	reg := NewRecipeRegistry(tmpDir)
	reg.Load()

	results := reg.Search("nmap")
	if len(results) == 0 {
		t.Error("Search('nmap') returned no results")
	}
	
	results = reg.Search("sql")
	if len(results) == 0 {
		t.Error("Search('sql') returned no results")
	}
}

func TestRecipeRegistry_Categories(t *testing.T) {
	tmpDir := t.TempDir()
	
	r1 := `{"id": "r1", "name": "R1", "description": "d", "category": "recon", "version": "1.0.0", "author": "t", "tags": [], "parameters": [], "risk_level": "low", "requires": [], "examples": []}`
	r2 := `{"id": "r2", "name": "R2", "description": "d", "category": "exploit", "version": "1.0.0", "author": "t", "tags": [], "parameters": [], "risk_level": "high", "requires": [], "examples": []}`
	
	os.WriteFile(filepath.Join(tmpDir, "r1.json"), []byte(r1), 0644)
	os.WriteFile(filepath.Join(tmpDir, "r2.json"), []byte(r2), 0644)

	reg := NewRecipeRegistry(tmpDir)
	reg.Load()
	
	cats := reg.Categories()
	hasRecon, hasExploit := false, false
	for _, c := range cats {
		if c == "recon" {
			hasRecon = true
		}
		if c == "exploit" {
			hasExploit = true
		}
	}
	if !hasRecon || !hasExploit {
		t.Errorf("Categories() = %v, expected custom categories 'recon' and 'exploit'", cats)
	}
}