package llmrec

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/Autumn-27/behemoth/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires PostgreSQL advisory lock 7337741002 on a pinned connection
// so parallel `go test ./...` runs serialize with db/agent/evidence/server.
func TestMain(m *testing.M) {
	os.Exit(runLLMRecTestSuite(m))
}

func runLLMRecTestSuite(m *testing.M) int {
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
