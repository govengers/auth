package postgresstore_test

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/apikey/postgresstore"
)

// ExampleNew issues a read-only key for a user and authenticates requests with it. Load builds the owner's
// identity from the application's users table; the key's scopes cap it. MigrationV1 runs in one of the
// application's goose migrations first.
func ExampleNew() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return
	}
	defer pool.Close()
	store, err := postgresstore.New(&postgresstore.Options{
		Pool:   pool,
		Prefix: "todo",
		Load: func(_ context.Context, ownerID uuid.UUID) (*auth.Identity, error) {
			// look the user up in your own table; a deleted one is &auth.Error{Kind: auth.ErrUnauthenticated}
			return &auth.Identity{UserID: ownerID, Active: true, Permissions: []auth.Permission{{Resource: auth.AllResources, Access: auth.AccessWrite}}}, nil
		},
	})
	if err != nil {
		return
	}
	text, key, err := store.Issue(ctx, uuid.New(), postgresstore.IssueRequest{
		Name:   "ci",
		Scopes: []auth.Permission{{Resource: "tasks", Access: auth.AccessRead}},
	})
	if err != nil {
		return
	}
	fmt.Println("show once:", text, "id:", key.ID)

	authenticator, err := apikey.New(&apikey.Options{Resolver: store.Resolve})
	if err != nil {
		return
	}
	_ = authenticator.Middleware()(http.NotFoundHandler()) // before the session.Guard
}

// ExampleStore_WithExecutor issues a key in the application's transaction, next to the audit entry naming it:
// both commit or neither does. Inside a govengers/livewire unit of work the executor is
// postgresadapter.TransactionFrom(ctx).
func ExampleStore_WithExecutor() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return
	}
	defer pool.Close()
	store, err := postgresstore.New(&postgresstore.Options{Pool: pool, Prefix: "todo", Load: func(_ context.Context, ownerID uuid.UUID) (*auth.Identity, error) {
		return &auth.Identity{UserID: ownerID, Active: true}, nil
	}})
	if err != nil {
		return
	}
	owner := uuid.New()
	err = pgx.BeginFunc(ctx, pool, func(transaction pgx.Tx) error {
		_, key, err := store.WithExecutor(transaction).Issue(ctx, owner, postgresstore.IssueRequest{
			Name:   "ci",
			Scopes: []auth.Permission{{Resource: "tasks", Access: auth.AccessRead}},
		})
		if err != nil {
			return err
		}
		_, err = transaction.Exec(ctx, `INSERT INTO audit_log (actor_id, action, object_id) VALUES ($1, 'issue_api_key', $2)`, owner, key.ID)
		return err
	})
	if err != nil {
		return
	}
}
