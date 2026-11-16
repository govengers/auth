package postgresbackend_test

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth/session"
	"github.com/govengers/auth/session/postgresbackend"
)

// ExampleNew shares sessions between replicas through PostgreSQL: every replica builds its Store on a
// backend on the same database. MigrationV1 runs in one of the application's goose migrations first;
// Sweep runs on a schedule (e.g. a govengers/jobs schedule every 10 minutes).
func ExampleNew() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return
	}
	defer pool.Close()
	backend, err := postgresbackend.New(&postgresbackend.Options{Pool: pool})
	if err != nil {
		return
	}
	key, err := session.ParseKey(os.Getenv("SESSION_ENCRYPTION_KEY"))
	if err != nil {
		return
	}
	_, _ = session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key})

	_, _ = backend.Sweep(ctx) // from the scheduled job
}
