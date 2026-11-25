package server

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/Autumn-27/behemoth/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) on a single pinned
// connection for the entire server test suite so cross-package DELETE/DDL races
// with db/agent/llmrec/evidence are avoided when running `go test ./...`.
func TestMain(m *testing.M) {
	os.Exit(runServerTestSuite(m))
}

func runServerTestSuite(m *testing.M) int {
	dsn, _, err := db.DSN()
	if err != nil {
		return m.Run()
	}
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
