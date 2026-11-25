package evidence

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/Autumn-27/behemoth/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Acquire the shared suite lock (7337741002) on a pinned connection BEFORE
// running db.Open so startup DDL never collides with parallel package tests.
func TestMain(m *testing.M) {
	if os.Getenv("BEHEMOTH_PG_DSN") == "" {
		os.Exit(m.Run())
	}
	os.Exit(runEvidenceSuite(m))
}

func runEvidenceSuite(m *testing.M) int {
	dsn := os.Getenv("BEHEMOTH_PG_DSN")
	if pool, err := sql.Open("pgx", dsn); err == nil {
		defer pool.Close()
		if conn, cerr := pool.Conn(context.Background()); cerr == nil {
			defer conn.Close()
			if _, lerr := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock(7337741002)`); lerr == nil {
				defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
			}
		}
	}
	pg, err := db.Open(dsn)
	if err != nil {
		panic(err)
	}
	defer pg.Close()
	return m.Run()
}
