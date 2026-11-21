// Package memory provides vector-based memory storage using pgvector.
package memory

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MemoryEntry represents a single memory entry with vector embedding.
type MemoryEntry struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Content    string    `json:"content"`
	Embedding  []float32 `json:"embedding"`
	Metadata   JSONMap   `json:"metadata"`
	Tags       []string  `json:"tags"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Similarity float32   `json:"similarity"`
}

// JSONMap is a flexible JSON metadata container.
type JSONMap map[string]interface{}

// VectorStore provides pgvector-backed memory operations.
type VectorStore struct {
	pool       *pgxpool.Pool
	dimensions int
}

// NewVectorStore creates a new vector store connection.
func NewVectorStore(pool *pgxpool.Pool, dims int) *VectorStore {
	if dims == 0 {
		dims = 1536
	}
	return &VectorStore{pool: pool, dimensions: dims}
}
