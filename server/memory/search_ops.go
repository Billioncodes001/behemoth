package memory

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Search finds similar entries using vector similarity.
func (vs *VectorStore) Search(ctx context.Context, queryEmbedding []float32, memType string, limit int) ([]MemoryEntry, error) {
	if limit == 0 {
		limit = 10
	}

	var rows interface{ Close() }
	var err error
	
	if memType != "" {
		rows, err = vs.pool.Query(ctx, `
			SELECT id, type, content, embedding, metadata, tags, created_at, expires_at,
				   1 - (embedding <=> $1::vector) as similarity
			FROM memory_entries
			WHERE type = $2 AND expires_at > NOW()
			ORDER BY embedding <=> $1::vector
			LIMIT $3
		`, queryEmbedding, memType, limit)
	} else {
		rows, err = vs.pool.Query(ctx, `
			SELECT id, type, content, embedding, metadata, tags, created_at, expires_at,
				   1 - (embedding <=> $1::vector) as similarity
			FROM memory_entries
			WHERE expires_at > NOW()
			ORDER BY embedding <=> $1::vector
			LIMIT $2
		`, queryEmbedding, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("vector search failed: %w", err)
	}
	defer rows.(interface{ Close() }).Close()

	var entries []MemoryEntry
	for rows.(interface{ Next() bool }).Next() {
		var e MemoryEntry
		var metadataJSON []byte
		
		r := rows.(interface {
			Scan(dest ...interface{}) error
		})
		
		err := r.Scan(
			&e.ID, &e.Type, &e.Content, &e.Embedding,
			&metadataJSON, &e.Tags, &e.CreatedAt, &e.ExpiresAt,
			&e.Similarity,
		)
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		
		json.Unmarshal(metadataJSON, &e.Metadata)
		entries = append(entries, e)
	}

	return entries, nil
}

// GetByID retrieves a specific memory entry.
func (vs *VectorStore) GetByID(ctx context.Context, id string) (*MemoryEntry, error) {
	var e MemoryEntry
	var metadataJSON []byte
	
	err := vs.pool.QueryRow(ctx, `
		SELECT id, type, content, embedding, metadata, tags, created_at, expires_at
		FROM memory_entries WHERE id = $1 AND expires_at > NOW()
	`, id).Scan(&e.ID, &e.Type, &e.Content, &e.Embedding,
		&metadataJSON, &e.Tags, &e.CreatedAt, &e.ExpiresAt)
	
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal(metadataJSON, &e.Metadata)
	return &e, nil
}

// Delete removes a memory entry by ID.
func (vs *VectorStore) Delete(ctx context.Context, id string) error {
	_, err := vs.pool.Exec(ctx, "DELETE FROM memory_entries WHERE id = $1", id)
	return err
}

// CleanupExpired removes all expired entries.
func (vs *VectorStore) CleanupExpired(ctx context.Context) (int64, error) {
	tag, err := vs.pool.Exec(ctx, "DELETE FROM memory_entries WHERE expires_at <= NOW()")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}