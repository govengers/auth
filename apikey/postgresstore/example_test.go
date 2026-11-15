package postgresstore_test

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
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
