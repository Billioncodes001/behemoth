package proxyv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// PGStore implements Store interface using PostgreSQL.
type PGStore struct {
	db *sql.DB
}

// NewPGStore creates a new PostgreSQL-backed store.
func NewPGStore(db *sql.DB) *PGStore {
	return &PGStore{db: db}
}

// InitTable creates the proxy_pool table if it doesn't exist.
func (s *PGStore) InitTable(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS proxy_pool_v2 (
		id SERIAL PRIMARY KEY,
		key VARCHAR(50) UNIQUE NOT NULL DEFAULT 'main',
		config JSONB NOT NULL DEFAULT '{}',
		proxies JSONB NOT NULL DEFAULT '[]',
		active_proxy_id VARCHAR(100),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_proxy_pool_key ON proxy_pool_v2(key);
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// LoadPool loads the pool state from PostgreSQL.
func (s *PGStore) LoadPool() (*proxyPersist, error) {
	query := `SELECT config, proxies, active_proxy_id FROM proxy_pool_v2 WHERE key = 'main' LIMIT 1`
	row := s.db.QueryRow(query)

	var configJSON, proxiesJSON, activeID sql.NullString
	if err := row.Scan(&configJSON, &proxiesJSON, &activeID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		} // No data yet
		return nil, fmt.Errorf("scan: %w", err)
	}

	persisted := &proxyPersist{
		Config: DefaultPoolConfig(),
		Active: activeID.String,
	}

	if configJSON.Valid && configJSON.String != "" && configJSON.String != "{}" {
		if err := json.Unmarshal([]byte(configJSON.String), &persisted.Config); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	if proxiesJSON.Valid && proxiesJSON.String != "" && proxiesJSON.String != "[]" {
		if err := json.Unmarshal([]byte(proxiesJSON.String), &persisted.Proxies); err != nil {
			return nil, fmt.Errorf("parse proxies: %w", err)
		}
	}

	return persisted, nil
}

// SavePool persists the pool state to PostgreSQL.
func (s *PGStore) SavePool(p *proxyPersist) error {
	configJSON, err := json.Marshal(p.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	proxiesJSON, err := json.Marshal(p.Proxies)
	if err != nil {
		return fmt.Errorf("marshal proxies: %w", err)
	}

	query := `
	INSERT INTO proxy_pool_v2 (key, config, proxies, active_proxy_id, updated_at)
	VALUES ('main', $1, $2, $3, NOW())
	ON CONFLICT (key) DO UPDATE SET
		config = EXCLUDED.config,
		proxies = EXCLUDED.proxies,
		active_proxy_id = EXCLUDED.active_proxy_id,
		updated_at = NOW()
	`
	_, err = s.db.Exec(query, configJSON, proxiesJSON, p.Active)
	if err != nil {
		return fmt.Errorf("save pool: %w", err)
	}
	return nil
}
