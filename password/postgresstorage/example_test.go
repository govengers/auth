package postgresstorage_test

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth/password"
	"github.com/govengers/auth/password/postgresstorage"
	"github.com/govengers/auth/session"
)

// ExampleNew keeps password users in PostgreSQL. MigrationV1 runs in one of the application's goose
// migrations first; the pool's search_path reaches its table.
func ExampleNew() {
	pool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		return
	}
	defer pool.Close()
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: pool})
	if err != nil {
		return
	}
	backend, err := session.NewMemoryBackend(nil)
	if err != nil {
		return
	}
	key, err := session.ParseKey(os.Getenv("SESSION_ENCRYPTION_KEY"))
	if err != nil {
		return
	}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key})
	if err != nil {
		return
	}
	_, _ = password.New(&password.Options{Sessions: store, Storage: storage})
}
