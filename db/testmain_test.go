package db

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) on a single pinned
// connection for the entire db test suite so parallel `go test ./...` runs
// serialize cleanly across db, agent, llmrec, evidence, and server packages.
func TestMain(m *testing.M) {
	os.Exit(runDBTestSuite(m))
}

func runDBTestSuite(m *testing.M) int {
	dsn, _, err := DSN()
	if err != nil {
		return m.Run()
	}
	_ = ensureDatabase(dsn)
	pool, err := sql.Open("pgx", dsn)
	if err != nil || pool.Ping() != nil {
		if pool != nil {
			_ = pool.Close()
		}
		return m.Run()
	}
	defer pool.Close()
	conn, err := pool.Conn(context.Background())
	if err != nil {
		return m.Run()
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock(7337741002)`); err != nil {
		return m.Run()
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
	return m.Run()
}
