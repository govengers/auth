// Command postgres is a password-login server that keeps everything in PostgreSQL, so any number of
// replicas share it: users in password/postgresstorage, sessions in session/postgresbackend, per-user API
// keys in apikey/postgresstore. Without DATABASE_URL it starts an embedded PostgreSQL 18 under
// sandbox/example-postgres for local development.
//
// Users register and log in with a password; a logged-in user issues keys with scopes (POST /api/keys) and
// scripts call the API with "Authorization: Bearer <key>", acting as that user capped by the key's scopes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"
	"github.com/govengers/config/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/apikey/postgresstore"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/password"
	"github.com/govengers/auth/password/postgresstorage"
	"github.com/govengers/auth/session"
	"github.com/govengers/auth/session/postgresbackend"
)

const (
	contentTypeHeader = "Content-Type"
	embeddedPort      = 5433
	sweepInterval     = 10 * time.Minute
)

// migrations stand in for the application's goose migrations: each library constant is one migration.
var migrations = []string{postgresbackend.MigrationV1, postgresstorage.MigrationV1, postgresstore.MigrationV1}

// fullAccess is what every user may do in this demo; a key's scopes narrow it.
var fullAccess = []auth.Permission{{Resource: auth.AllResources, Access: auth.AccessWrite}}

// serverOptions is what newServer needs; main fills it from the environment.
type serverOptions struct {
	EncryptionKey  []byte // 32 bytes, see session.ParseKey; the same on every replica
	InsecureCookie bool   // drops Secure for plain http off loopback; local development only
	Pool           *pgxpool.Pool
}

// server is the HTTP handler plus the session backend, whose Sweep main schedules.
type server struct {
	handler http.Handler
	backend *postgresbackend.Backend
}

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var encryptionKey, databaseURL, address string
	var insecureCookie bool
	err := config.LoadConfig([]config.Value{
		config.String("SESSION_ENCRYPTION_KEY").NotEmpty().Sensitive().Into(&encryptionKey), // openssl rand -base64 32
		config.Bool("SESSION_INSECURE_COOKIE").Default(false).Into(&insecureCookie),
		config.String("DATABASE_URL").Default("").Sensitive().Into(&databaseURL), // empty: embedded PostgreSQL
		config.String("ADDRESS").Default(":8080").Into(&address),
	})
	if err != nil {
		return err
	}
	key, err := session.ParseKey(encryptionKey)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if databaseURL == "" {
		database := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
			Version(embeddedpostgres.V18).Port(embeddedPort).RuntimePath("sandbox/example-postgres"))
		if err := database.Start(); err != nil {
			return fmt.Errorf("start the embedded PostgreSQL: %w", err)
		}
		defer func() { _ = database.Stop() }() // the process ends either way
		databaseURL = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", embeddedPort)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := migrate(ctx, pool); err != nil {
		return err
	}
	server, err := newServer(&serverOptions{EncryptionKey: key, InsecureCookie: insecureCookie, Pool: pool})
	if err != nil {
		return err
	}
	go sweep(ctx, server.backend)
	httpServer := newHTTPServer(address, server.handler)
	go func() {
		<-ctx.Done()
		_ = httpServer.Close() // shutting down
	}()
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// migrate applies the library migrations once; a real application runs them from goose.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	var applied bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('govengers_auth_sessions') IS NOT NULL`).Scan(&applied); err != nil || applied {
		return err
	}
	for _, migration := range migrations {
		if err := pgx.BeginFunc(ctx, pool, func(transaction pgx.Tx) error {
			_, err := transaction.Exec(ctx, migration)
			return err
		}); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// sweep deletes expired sessions every sweepInterval; with several replicas, run it from one (a govengers/jobs
// schedule does that).
func sweep(ctx context.Context, backend *postgresbackend.Backend) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := backend.Sweep(ctx); err != nil {
				slog.Error("sweep expired sessions", "error", err)
			}
		}
	}
}

// newHTTPServer bounds what one client can hold: slow or endless requests, idle connections, header bytes.
func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		MaxHeaderBytes:    64 << 10,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// newServer wires the three stores, the password provider, the key authenticator, the Guard and the routes.
func newServer(options *serverOptions) (*server, error) {
	backend, err := postgresbackend.New(&postgresbackend.Options{Pool: options.Pool})
	if err != nil {
		return nil, err
	}
	sessions, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: options.EncryptionKey, InsecureCookie: options.InsecureCookie})
	if err != nil {
		return nil, err
	}
	users, err := postgresstorage.New(&postgresstorage.Options{Pool: options.Pool})
	if err != nil {
		return nil, err
	}
	provider, err := password.New(&password.Options{
		Sessions:           sessions,
		Storage:            users,
		EnableRegistration: true, // POST /auth/password/register: open sign-up for the demo
		OnLogin:            grantPermissions,
	})
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{Store: sessions, Refreshers: []session.Refresher{provider}})
	if err != nil {
		return nil, err
	}
	keys, err := postgresstore.New(&postgresstore.Options{Pool: options.Pool, Prefix: "example", Load: loadOwner(users)})
	if err != nil {
		return nil, err
	}
	authenticator, err := apikey.New(&apikey.Options{Resolver: keys.Resolve})
	if err != nil {
		return nil, err
	}

	// keyOrSession accepts a key or a session; sessionOnly a session (a key must not issue keys).
	keyOrSession := func(handler http.Handler) http.Handler { return authenticator.Middleware()(guard.RequireAPI()(handler)) }
	sessionOnly := guard.RequireAPI()
	keyRoutes := &keyRoutes{keys: keys}
	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes())
	serveMux.Handle("GET /api/me", keyOrSession(auth.IdentityHandler()))
	serveMux.Handle("GET /api/tasks", keyOrSession(authorize(authorization.HasPermission("tasks", auth.AccessRead))(http.HandlerFunc(listTasks))))
	serveMux.Handle("POST /api/tasks", keyOrSession(authorize(authorization.HasPermission("tasks", auth.AccessWrite))(http.HandlerFunc(createTask))))
	serveMux.Handle("GET /api/keys", sessionOnly(http.HandlerFunc(keyRoutes.list)))
	serveMux.Handle("POST /api/keys", sessionOnly(http.HandlerFunc(keyRoutes.issue)))
	serveMux.Handle("DELETE /api/keys/{id}", sessionOnly(http.HandlerFunc(keyRoutes.revoke)))
	return &server{handler: serveMux, backend: backend}, nil
}

// grantPermissions is the OnLogin hook: it returns a Clone and keeps UserID, which the password provider
// requires. A real application reads the permissions from its own tables.
func grantPermissions(_ context.Context, identity *auth.Identity) (*auth.Identity, error) {
	granted := identity.Clone()
	granted.Permissions = slices.Clone(fullAccess)
	return granted, nil
}

// loadOwner is the key store's Load: the owner's identity as a login would build it. A deleted user's keys stop
// working at once.
func loadOwner(users *postgresstorage.Storage) postgresstore.Loader {
	return func(ctx context.Context, ownerID uuid.UUID) (*auth.Identity, error) {
		user, err := users.GetUserByID(ctx, ownerID)
		if errors.Is(err, password.ErrUserNotFound) {
			return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "key owner deleted"}
		}
		if err != nil {
			return nil, err
		}
		identity := &auth.Identity{UserID: user.ID, Active: true, Permissions: slices.Clone(fullAccess)}
		if user.Username != nil {
			identity.Username = *user.Username
		}
		return identity, nil
	}
}

// authorize is net/http middleware that runs check after the Guard: 401, 403 or 500 JSON when it refuses.
func authorize(check authorization.Check) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if err := check(request.Context()); err != nil {
				auth.WriteError(writer, err)
				return
			}
			next.ServeHTTP(writer, request)
		})
	}
}

func listTasks(writer http.ResponseWriter, request *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"owner": auth.IdentityFrom(request.Context()).Username, "tasks": []string{}})
}

func createTask(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusCreated)
}

// keyRoutes let a logged-in user manage their own keys.
type keyRoutes struct {
	keys *postgresstore.Store
}

type issueBody struct {
	Name   string            `json:"name"`
	Scopes []auth.Permission `json:"scopes"` // text form, e.g. "tasks:read"
}

type keyBody struct {
	ID     uuid.UUID         `json:"id"`
	Name   string            `json:"name"`
	Scopes []auth.Permission `json:"scopes"`
	Key    string            `json:"key,omitempty"` // only in the answer to POST
}

func (k *keyRoutes) issue(writer http.ResponseWriter, request *http.Request) {
	var body issueBody
	if err := json.NewDecoder(io.LimitReader(request.Body, 64<<10)).Decode(&body); err != nil {
		auth.WriteError(writer, &auth.Error{Kind: auth.ErrInvalidRequest, Err: err})
		return
	}
	owner := auth.IdentityFrom(request.Context()).UserID
	text, key, err := k.keys.Issue(request.Context(), owner, postgresstore.IssueRequest{Name: body.Name, Scopes: body.Scopes})
	if err != nil {
		auth.WriteError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, keyBody{ID: key.ID, Name: key.Name, Scopes: key.Scopes, Key: text})
}

func (k *keyRoutes) list(writer http.ResponseWriter, request *http.Request) {
	keys, err := k.keys.List(request.Context(), auth.IdentityFrom(request.Context()).UserID)
	if err != nil {
		auth.WriteError(writer, err)
		return
	}
	listed := make([]keyBody, len(keys))
	for index, key := range keys {
		listed[index] = keyBody{ID: key.ID, Name: key.Name, Scopes: key.Scopes}
	}
	writeJSON(writer, http.StatusOK, listed)
}

func (k *keyRoutes) revoke(writer http.ResponseWriter, request *http.Request) {
	id, err := uuid.Parse(request.PathValue("id"))
	if err != nil {
		auth.WriteError(writer, &auth.Error{Kind: auth.ErrInvalidRequest, Err: err})
		return
	}
	err = k.keys.Revoke(request.Context(), auth.IdentityFrom(request.Context()).UserID, id)
	switch {
	case errors.Is(err, postgresstore.ErrKeyNotFound):
		writer.WriteHeader(http.StatusNotFound)
	case err != nil:
		auth.WriteError(writer, err)
	default:
		writer.WriteHeader(http.StatusNoContent)
	}
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set(contentTypeHeader, "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body) // a failed write means the client left
}
