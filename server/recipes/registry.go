package recipes

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed tools/*.json
var builtinRecipesFS embed.FS

// ToolRecipe defines a tool that can be used by agents.
type ToolRecipe struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Version     string   `json:"version"`
	Author      string   `json:"author"`
	Tags        []string `json:"tags"`

	// Execution config
	Command string `json:"command,omitempty"` // Shell command template
	Script  string `json:"script,omitempty"`  // Inline script
	Handler string `json:"handler,omitempty"` // Go handler name

	// Parameters
	Parameters []RecipeParameter `json:"parameters"`

	// Output handling
	ParseOutput  bool   `json:"parse_output,omitempty"`
	OutputFormat string `json:"output_format,omitempty"` // json, text, table

	// Metadata
	RiskLevel string          `json:"risk_level"` // low, medium, high, critical
	Requires  []string        `json:"requires"`   // Required capabilities
	Examples  []RecipeExample `json:"examples"`

	// Internal
	FilePath string `json:"-"`
}

// RecipeParameter is a parameter definition.
type RecipeParameter struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // string, int, bool, file, select
	Required    bool     `json:"required"`
	Default     any      `json:"default,omitempty"`
	Description string   `json:"description"`
	Options     []string `json:"options,omitempty"` // For select type
}

// RecipeExample is an example usage.
type RecipeExample struct {
	Input       map[string]any `json:"input"`
	Output      string         `json:"output,omitempty"`
	Description string         `json:"description"`
}

// RecipeRegistry manages tool recipes.
type RecipeRegistry struct {
	mu      sync.RWMutex
	recipes map[string]*ToolRecipe
	index   map[string][]*ToolRecipe // category -> recipes
	tags    map[string][]*ToolRecipe // tag -> recipes
	dir     string
}

// NewRecipeRegistry creates a new recipe registry.
func NewRecipeRegistry(dir string) *RecipeRegistry {
	return &RecipeRegistry{
		recipes: make(map[string]*ToolRecipe),
		index:   make(map[string][]*ToolRecipe),
		tags:    make(map[string][]*ToolRecipe),
		dir:     dir,
	}
}

// Load loads all built-in embedded recipes and any custom recipes from the directory.
func (r *RecipeRegistry) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	addRecipe := func(recipe ToolRecipe, path string) {
		if recipe.ID == "" {
			return
		}
		if _, exists := r.recipes[recipe.ID]; exists {
			return
		}
		cp := recipe
		cp.FilePath = path
		r.recipes[cp.ID] = &cp
		r.index[cp.Category] = append(r.index[cp.Category], &cp)
		for _, tag := range cp.Tags {
			r.tags[tag] = append(r.tags[tag], &cp)
		}
	}

	// 1. Load embedded built-in recipes first
	if embeddedEntries, err := builtinRecipesFS.ReadDir("tools"); err == nil {
		for _, entry := range embeddedEntries {
			if entry.IsDir() {
				continue
			}
			data, err := builtinRecipesFS.ReadFile("tools/" + entry.Name())
			if err != nil {
				continue
			}
			var recipe ToolRecipe
			if err := yamlUnmarshal(data, &recipe); err != nil {
				continue
			}
			addRecipe(recipe, "builtin:"+entry.Name())
		}
	}

	// 2. Load user-supplied recipes from r.dir (if present)
	if r.dir == "" {
		return nil
	}
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No custom recipes dir yet
		}
		return fmt.Errorf("read recipes dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}

		path := filepath.Join(r.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Skip unreadable files
		}

		var recipe ToolRecipe
		if err := yamlUnmarshal(data, &recipe); err != nil {
			continue // Skip invalid YAML
		}

		addRecipe(recipe, path)
	}

	return nil
}

// Get returns a recipe by ID.
func (r *RecipeRegistry) Get(id string) (*ToolRecipe, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	recipe, ok := r.recipes[id]
	return recipe, ok
}

// List returns all recipes.
func (r *RecipeRegistry) List() []*ToolRecipe {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*ToolRecipe, 0, len(r.recipes))
	for _, recipe := range r.recipes {
		result = append(result, recipe)
	}
	return result
}

// ByCategory returns recipes in a category.
func (r *RecipeRegistry) ByCategory(category string) []*ToolRecipe {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.index[category]
}

// Categories returns all categories.
func (r *RecipeRegistry) Categories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cats := make([]string, 0, len(r.index))
	for cat := range r.index {
		cats = append(cats, cat)
	}
	return cats
}

// Search searches recipes by name, description, or tags.
func (r *RecipeRegistry) Search(query string) []*ToolRecipe {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []*ToolRecipe
	for _, recipe := range r.recipes {
		if matchQuery(recipe, query) {
			results = append(results, recipe)
		}
	}
	return results
}

// Count returns the number of loaded recipes.
func (r *RecipeRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.recipes)
}

func matchQuery(recipe *ToolRecipe, query string) bool {
	// Simple contains matching (case-insensitive would be better but this works for now)
	if contains(recipe.Name, query) || contains(recipe.Description, query) || contains(recipe.ID, query) {
		return true
	}
	for _, tag := range recipe.Tags {
		if contains(tag, query) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func yamlUnmarshal(data []byte, v interface{}) error {
	if err := json.Unmarshal(data, v); err == nil {
		return nil
	}
	return yaml.Unmarshal(data, v)
}
