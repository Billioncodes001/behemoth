package factgraph

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Graph manages a collection of facts with relationships.
type Graph struct {
	mu      sync.RWMutex
	facts   map[string]*Fact     // ID -> Fact
	index   map[FactKind][]*Fact // Kind -> Facts
	search  map[string][]*Fact   // Tag/Title -> Facts
	taskIdx map[string][]*Fact   // TaskID -> Facts
}

// NewGraph creates a new fact graph.
func NewGraph() *Graph {
	return &Graph{
		facts:   make(map[string]*Fact),
		index:   make(map[FactKind][]*Fact),
		search:  make(map[string][]*Fact),
		taskIdx: make(map[string][]*Fact),
	}
}

// Add adds a fact to the graph.
func (g *Graph) Add(fact *Fact) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.facts[fact.ID]; exists {
		return // Already exists
	}

	fact.CreatedAt = time.Now()
	fact.UpdatedAt = time.Now()

	g.facts[fact.ID] = fact
	g.index[fact.Kind] = append(g.index[fact.Kind], fact)

	// Index by task
	if fact.TaskID != "" {
		g.taskIdx[fact.TaskID] = append(g.taskIdx[fact.TaskID], fact)
	}

	// Index by tags and title for search
	g.search[strings.ToLower(fact.Title)] = append(g.search[strings.ToLower(fact.Title)], fact)
	for _, tag := range fact.Tags {
		g.search[strings.ToLower(tag)] = append(g.search[strings.ToLower(tag)], fact)
	}
}

// Get retrieves a fact by ID.
func (g *Graph) Get(id string) (*Fact, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	f, ok := g.facts[id]
	return f, ok
}

// Remove removes a fact by ID.
func (g *Graph) Remove(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	fact, ok := g.facts[id]
	if !ok {
		return
	}

	delete(g.facts, id)

	// Remove from kind index
	if facts := g.index[fact.Kind]; facts != nil {
		for i, f := range facts {
			if f.ID == id {
				g.index[fact.Kind] = append(facts[:i], facts[i+1:]...)
				break
			}
		}
	}

	// Remove from task index
	if fact.TaskID != "" {
		if facts := g.taskIdx[fact.TaskID]; facts != nil {
			for i, f := range facts {
				if f.ID == id {
					g.taskIdx[fact.TaskID] = append(facts[:i], facts[i+1:]...)
					break
				}
			}
		}
	}
}

// List returns all facts.
func (g *Graph) List() []*Fact {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]*Fact, 0, len(g.facts))
	for _, f := range g.facts {
		result = append(result, f)
	}
	return result
}

// ByKind returns all facts of a specific kind.
func (g *Graph) ByKind(kind FactKind) []*Fact {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.index[kind]
}

// ByTask returns all facts for a task.
func (g *Graph) ByTask(taskID string) []*Fact {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.taskIdx[taskID]
}

// Search finds facts matching a query.
func (g *Graph) Search(query string) []*Fact {
	g.mu.RLock()
	defer g.mu.RUnlock()

	query = strings.ToLower(query)
	var results []*Fact
	seen := make(map[string]bool)

	// Search in indexed fields
	if facts, ok := g.search[query]; ok {
		for _, f := range facts {
			if !seen[f.ID] {
				results = append(results, f)
				seen[f.ID] = true
			}
		}
	}

	// Fallback: search all facts
	if len(results) == 0 {
		for _, f := range g.facts {
			if strings.Contains(strings.ToLower(f.Title), query) ||
				strings.Contains(strings.ToLower(f.Content), query) {
				results = append(results, f)
			}
		}
	}

	return results
}

// Update updates an existing fact.
func (g *Graph) Update(id string, fn func(*Fact)) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	fact, ok := g.facts[id]
	if !ok {
		return fmt.Errorf("fact not found: %s", id)
	}

	fn(fact)
	fact.UpdatedAt = time.Now()
	return nil
}

// Link creates a relationship between two facts.
func (g *Graph) Link(sourceID, targetID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	source, ok := g.facts[sourceID]
	if !ok {
		return fmt.Errorf("source fact not found: %s", sourceID)
	}

	target, ok := g.facts[targetID]
	if !ok {
		return fmt.Errorf("target fact not found: %s", targetID)
	}

	// Add to derived IDs if not already present
	for _, id := range source.DerivedIDs {
		if id == targetID {
			return nil // Already linked
		}
	}

	source.DerivedIDs = append(source.DerivedIDs, targetID)
	target.SourceIDs = append(target.SourceIDs, sourceID)

	return nil
}

// Stats returns graph statistics.
func (g *Graph) Stats() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := make(map[string]int)
	stats["total"] = len(g.facts)

	for kind, facts := range g.index {
		stats[string(kind)] = len(facts)
	}

	return stats
}

// Count returns total number of facts.
func (g *Graph) Count() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.facts)
}

// Helper functions

func generateFactID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "fact-" + hex.EncodeToString(b)[:12]
}

func maskString(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

func joinStrings(strs []string, sep string) string {
	return strings.Join(strs, sep)
}
