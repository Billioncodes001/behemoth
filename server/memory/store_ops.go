package memory

import (
	"context"
	"encoding/json"
	"fmt"
)

// Initialize creates the necessary tables and extensions.
func (vs *VectorStore) Initialize(ctx context.Context) error {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS vector`,
		fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS memory_entries (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			content TEXT NOT NULL,
			embedding vector(%d),
			metadata jsonb DEFAULT '{}',
			tags text[] DEFAULT '{}',
			created_at TIMESTAMPTZ DEFAULT NOW(),
			expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '24 hours'
		)`, vs.dimensions),
		`CREATE INDEX IF NOT EXISTS idx_memory_type ON memory_entries(type)`,
		`CREATE INDEX IF NOT EXISTS idx_memory_tags ON memory_entries USING GIN(tags)`,
	}

	for _, q := range queries {
		if _, err := vs.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("vector store init failed: %w", err)
		}
	}
	return nil
}

// Store saves a new memory entry with its embedding.
func (vs *VectorStore) Store(ctx context.Context, entry MemoryEntry) error {
	metadataJSON, _ := json.Marshal(entry.Metadata)

	query := `
		INSERT INTO memory_entries (id, type, content, embedding, metadata, tags, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			content = EXCLUDED.content,
			embedding = EXCLUDED.embedding,
			metadata = EXCLUDED.metadata,
			tags = EXCLUDED.tags,
			expires_at = EXCLUDED.expires_at
	`

	_, err := vs.pool.Exec(ctx, query,
		entry.ID, entry.Type, entry.Content,
		entry.Embedding, metadataJSON, entry.Tags,
		entry.CreatedAt, entry.ExpiresAt,
	)
	return err
}
