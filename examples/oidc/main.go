// Command oidc is a minimal server with OpenID Connect login (net/http), optionally enriched from the
// Keycloak Admin API: sessions in memory, a JSON API behind session.Guard.RequireAPI, a page behind
// RequireUI that starts the login, a route for one realm role, and logout at the IdP. Register
// <EXTERNAL_URL>/auth/oidc/sso/callback as redirect URI at the IdP. Replace the memory session backend
// with redisbackend before you run more than one replica.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/govengers/config/v2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/oidc"
	"github.com/govengers/auth/oidc/keycloak"
	"github.com/govengers/auth/session"
)

// serverOptions is what newServer needs; main fills it from the environment.
type serverOptions struct {
	EncryptionKey       []byte // 32 bytes, see session.ParseKey; the same on every replica
	ExternalURL         string // public origin of this server, e.g. https://app.example.com
	Issuer              string // e.g. https://keycloak.example.com/realms/example; https, or http on loopback
	ClientID            string
	ClientSecret        string
	AllowedEmailDomains []string          // optional: only verified emails of these domains log in; empty allows every account of the IdP
	Keycloak            *keycloak.Options // optional: read roles, groups and attributes from the Keycloak Admin API
}

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var encryptionKey, address string
	var options serverOptions
	var keycloakOptions keycloak.Options
	err := config.LoadConfig([]config.Value{
		config.String("SESSION_ENCRYPTION_KEY").NotEmpty().Sensitive().Into(&encryptionKey), // openssl rand -base64 32
		config.String("EXTERNAL_URL").NotEmpty().Into(&options.ExternalURL),
		config.String("OIDC_ISSUER").NotEmpty().Into(&options.Issuer),
		config.String("OIDC_CLIENT_ID").NotEmpty().Into(&options.ClientID),
		config.String("OIDC_CLIENT_SECRET").NotEmpty().Sensitive().Into(&options.ClientSecret),
		config.StringArray("OIDC_ALLOWED_EMAIL_DOMAINS").Default(nil).Into(&options.AllowedEmailDomains), // set it for Google, or any Google account gets in
		config.String("KEYCLOAK_URL").Default("").Into(&keycloakOptions.URL),                             // empty: no enrichment
		config.String("KEYCLOAK_REALM").Default("").Into(&keycloakOptions.Realm),
		config.String("KEYCLOAK_CLIENT_ID").Default("").Into(&keycloakOptions.ClientID), // a service account client, not the login client
		config.String("KEYCLOAK_CLIENT_SECRET").Default("").Sensitive().Into(&keycloakOptions.ClientSecret),
		config.String("ADDRESS").Default(":8080").Into(&address),
	})
	if err != nil {
		return err
	}
	if options.EncryptionKey, err = session.ParseKey(encryptionKey); err != nil {
		return err
	}
	if keycloakOptions.URL != "" {
		options.Keycloak = &keycloakOptions
	}
	handler, err := newServer(context.Background(), &options)
	if err != nil {
		return err
	}
	server := &http.Server{ // every phase of a connection is bounded, so slow or idle clients cannot hold it
		Addr:              address,
		Handler:           handler,
		MaxHeaderBytes:    64 << 10,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return server.ListenAndServe()
}

// newServer wires sessions, the OIDC provider (discovery runs here, ctx bounds it), the Guard and the
// application routes.
func newServer(ctx context.Context, options *serverOptions) (http.Handler, error) {
	backend, err := session.NewMemoryBackend(nil) // one replica only; redisbackend.New for more
	if err != nil {
		return nil, err
	}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: options.EncryptionKey})
	if err != nil {
		return nil, err
	}
	var onLogin auth.Hook
	if options.Keycloak != nil {
		enricher, err := keycloak.New(options.Keycloak)
		if err != nil {
			return nil, err
		}
		onLogin = enricher.Enrich // replaces OIDCRoles, OIDCClientRoles, Groups and Attributes; 403 for missing Required* roles
	}
	provider, err := oidc.New(ctx, &oidc.Options{
		Name:                "sso", // Identity.Provider and the route prefix /auth/oidc/sso
		Issuer:              options.Issuer,
		ClientID:            options.ClientID,
		ClientSecret:        options.ClientSecret,
		ExternalURL:         options.ExternalURL,
		AllowedEmailDomains: options.AllowedEmailDomains,
		Sessions:            store,
		OnLogin:             onLogin,
	})
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{Store: store, LoginURL: provider.LoginURL()})
	if err != nil {
		return nil, err
	}

	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes()) // GET /auth/oidc/sso/{login,callback,logout,frontchannel-logout}
	serveMux.Handle("GET /auth/me", guard.RequireAPI()(auth.IdentityHandler()))
	serveMux.Handle("GET /api/notes", guard.RequireAPI()(http.HandlerFunc(listNotes)))
	serveMux.Handle("DELETE /api/notes", guard.RequireAPI()(authorize(authorization.HasOIDCRole("admin"))(http.HandlerFunc(deleteNotes))))
	serveMux.Handle("GET /{$}", guard.RequireUI()(http.HandlerFunc(home)))
	return serveMux, nil
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
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"owner": identity.Username, "notes": []string{}}) // a failed write means the client left
}

func deleteNotes(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusNoContent)
}

func home(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(writer, "hello %s\n", auth.IdentityFrom(request.Context()).Username) // a failed write means the client left
}
