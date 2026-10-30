// Command password is a minimal server with password login (net/http): users in password.MemoryStorage,
// sessions in memory, a JSON API behind session.Guard.RequireAPI, a page behind RequireUI, an admin-only
// route and logout. Replace MemoryStorage with your own password.Storage on your database
// (docs/migration.md has the SQL for every method) and the memory session backend with redisbackend
// before you run more than one replica.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/govengers/config/v2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/password"
	"github.com/govengers/auth/session"
)

const contentTypeHeader = "Content-Type"

// serverOptions is what newServer needs; main fills it from the environment.
type serverOptions struct {
	EncryptionKey   []byte           // 32 bytes, see session.ParseKey; the same on every replica
	InsecureCookie  bool             // drops Secure for plain http off loopback; local development only
	Storage         password.Storage // your users table
	AdministratorID uuid.UUID        // the user grantRoles makes an admin
}

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var encryptionKey, administratorPassword, address string
	var insecureCookie bool
	err := config.LoadConfig([]config.Value{
		config.String("SESSION_ENCRYPTION_KEY").NotEmpty().Sensitive().Into(&encryptionKey), // openssl rand -base64 32
		config.Bool("SESSION_INSECURE_COOKIE").Default(false).Into(&insecureCookie),
		config.String("ADMINISTRATOR_PASSWORD").NotEmpty().Sensitive().Into(&administratorPassword), // at least 12 characters (createUser checks)
		config.String("ADDRESS").Default(":8080").Into(&address),
	})
	if err != nil {
		return err
	}
	key, err := session.ParseKey(encryptionKey)
	if err != nil {
		return err
	}
	storage := password.NewMemoryStorage()
	administratorID, err := createUser(context.Background(), storage, "admin", administratorPassword)
	if err != nil {
		return err
	}
	handler, err := newServer(&serverOptions{EncryptionKey: key, InsecureCookie: insecureCookie, Storage: storage, AdministratorID: administratorID})
	if err != nil {
		return err
	}
	return newHTTPServer(address, handler).ListenAndServe()
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

// createUser stores a user with an Argon2id hash of plainPassword, which must satisfy the provider's password
// policy (the default, as newServer configures it); your application does this in its own sign-up or admin flow
// (or enables the provider's registration route).
func createUser(ctx context.Context, storage password.Storage, username, plainPassword string) (uuid.UUID, error) {
	if err := (password.Policy{}).Validate(plainPassword); err != nil {
		return uuid.Nil, fmt.Errorf("password of %s: %w", username, err)
	}
	hash, err := password.Hash(plainPassword, password.DefaultParameters())
	if err != nil {
		return uuid.Nil, err
	}
	user := &password.User{ID: uuid.New(), Username: &username, PasswordHash: hash}
	return user.ID, storage.CreateUser(ctx, user)
}

// newServer wires sessions, the password provider, the Guard and the application routes.
func newServer(options *serverOptions) (http.Handler, error) {
	backend, err := session.NewMemoryBackend(nil) // one replica only; redisbackend.New for more
	if err != nil {
		return nil, err
	}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: options.EncryptionKey, InsecureCookie: options.InsecureCookie})
	if err != nil {
		return nil, err
	}
	provider, err := password.New(&password.Options{
		Sessions:           store,
		Storage:            options.Storage,
		EnableRegistration: true,                                                   // POST /auth/password/register: open sign-up for the demo
		TOTP:               password.TOTPOptions{Enabled: true, Issuer: "Example"}, // optional second factor
		OnLogin:            grantRoles(options.AdministratorID),
	})
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{
		Store:      store,
		LoginURL:   "/login",                      // where RequireUI sends anonymous browsers
		Refreshers: []session.Refresher{provider}, // a deleted user loses access within a minute
	})
	if err != nil {
		return nil, err
	}

	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes()) // the provider reads the session itself: no Guard in front
	serveMux.Handle("GET /auth/me", guard.RequireAPI()(auth.IdentityHandler()))
	serveMux.Handle("GET /api/notes", guard.RequireAPI()(http.HandlerFunc(listNotes)))
	serveMux.Handle("DELETE /api/notes", guard.RequireAPI()(authorize(authorization.IsAdmin())(http.HandlerFunc(deleteNotes))))
	serveMux.Handle("GET /{$}", guard.RequireUI()(http.HandlerFunc(home)))
	serveMux.HandleFunc("GET /login", loginPage)
	return serveMux, nil
}

// grantRoles is the OnLogin hook: it returns a Clone (hooks must not mutate their argument) and keeps
// UserID, which the password provider requires. A real application reads the roles from its own tables.
func grantRoles(administratorID uuid.UUID) auth.Hook {
	return func(_ context.Context, identity *auth.Identity) (*auth.Identity, error) {
		granted := identity.Clone()
		if granted.UserID == administratorID {
			granted.Roles = append(granted.Roles, auth.RoleAdmin)
		}
		return granted, nil
	}
}

// authorize is net/http middleware that runs check after the Guard: 401, 403 or 500 JSON when it refuses.
func authorize(check authorization.Check) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if err := check(request.Context()); err != nil {
				auth.WriteError(writer, err) // generic body; the Reason stays server-side
				return
			}
			next.ServeHTTP(writer, request)
		})
	}
}

func listNotes(writer http.ResponseWriter, request *http.Request) {
	identity := auth.IdentityFrom(request.Context()) // never nil behind the Guard
	writer.Header().Set(contentTypeHeader, "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"owner": identity.Username, "notes": []string{}}) // a failed write means the client left
}

func deleteNotes(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusNoContent)
}

func home(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set(contentTypeHeader, "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(writer, "hello %s\n", auth.IdentityFrom(request.Context()).Username) // a failed write means the client left
}

// loginPage stands in for your frontend's login form, which posts {"identifier","password"} as JSON to
// /auth/password/login.
func loginPage(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set(contentTypeHeader, "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(writer, "POST {\"identifier\",\"password\"} to /auth/password/login") // a failed write means the client left
}
