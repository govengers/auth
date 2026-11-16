package postgresstorage_test

import (
	"context"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// ExampleStorage_WithExecutor creates a user's credentials, the application's profile row and its audit entry
// in one transaction: all three commit or none does.
func ExampleStorage_WithExecutor() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return
	}
	defer pool.Close()
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: pool})
	if err != nil {
		return
	}
	hash, err := password.Hash("a long passphrase", password.DefaultParameters())
	if err != nil {
		return
	}
	username := "ada"
	user := &password.User{ID: uuid.New(), Username: &username, PasswordHash: hash}
	err = pgx.BeginFunc(ctx, pool, func(transaction pgx.Tx) error {
		if err := storage.WithExecutor(transaction).CreateUser(ctx, user); err != nil {
			return err // password.ErrUserExists for a taken username
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO users (id, display_name) VALUES ($1, $2)`, user.ID, "Ada"); err != nil {
			return err
		}
		_, err := transaction.Exec(ctx, `INSERT INTO audit_log (action, object_id) VALUES ('create_user', $1)`, user.ID)
		return err
	})
	if err != nil {
		return
	}
}
