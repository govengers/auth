// Command github is a minimal gin server with GitHub OAuth login and team checks: sessions in memory,
// a JSON API behind session.Guard.RequireAPI, a page behind RequireUI that starts the login, an
// admin-only route for AdminTeams members, logout, and outcomes recorded on the request's wide event.
// Register <EXTERNAL_URL>/auth/github/callback as the OAuth app's callback URL. Replace the memory
// session backend with redisbackend before you run more than one replica.
package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/govengers/config/v2"
	wideevent "github.com/mxcd/go-wide-event-logger"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/ginadapter"
	"github.com/govengers/auth/github"
	"github.com/govengers/auth/session"
)

// serverOptions is what newServer needs; main fills it from the environment.
type serverOptions struct {
	EncryptionKey []byte // 32 bytes, see session.ParseKey; the same on every replica
	ExternalURL   string // public origin of this server, e.g. https://app.example.com
	ClientID      string // the GitHub OAuth app
	ClientSecret  string
	AllowedTeams  []string // "org/team-slug"; nobody else gets a session
	AdminTeams    []string // members (of an allowed team too) get auth.RoleAdmin
	AuthorizeURL  string   // GitHub Enterprise; empty means github.com (AuthorizeURL, TokenURL and APIURL)
	TokenURL      string
	APIURL        string
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
	err := config.LoadConfig([]config.Value{
		config.String("SESSION_ENCRYPTION_KEY").NotEmpty().Sensitive().Into(&encryptionKey), // openssl rand -base64 32
		config.String("EXTERNAL_URL").NotEmpty().Into(&options.ExternalURL),
		config.String("GITHUB_CLIENT_ID").NotEmpty().Into(&options.ClientID),
		config.String("GITHUB_CLIENT_SECRET").NotEmpty().Sensitive().Into(&options.ClientSecret),
		config.StringArray("GITHUB_ALLOWED_TEAMS").NotEmpty().Into(&options.AllowedTeams),
		config.StringArray("GITHUB_ADMIN_TEAMS").Default(nil).Into(&options.AdminTeams),
		config.String("ADDRESS").Default(":8080").Into(&address),
	})
	if err != nil {
		return err
	}
	if options.EncryptionKey, err = session.ParseKey(encryptionKey); err != nil {
		return err
	}
	gin.SetMode(gin.ReleaseMode)
	handler, err := newServer(&options)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	return server.ListenAndServe()
}

// newServer wires sessions, the GitHub provider, the Guard and the application routes on gin.
func newServer(options *serverOptions) (http.Handler, error) {
	backend, err := session.NewMemoryBackend(nil) // one replica only; redisbackend.New for more
	if err != nil {
		return nil, err
	}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: options.EncryptionKey})
	if err != nil {
		return nil, err
	}
	provider, err := github.New(&github.Options{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		ExternalURL:  options.ExternalURL,
		AllowedTeams: options.AllowedTeams,
		AdminTeams:   options.AdminTeams,
		AuthorizeURL: options.AuthorizeURL,
		TokenURL:     options.TokenURL,
		APIURL:       options.APIURL,
		Sessions:     store,
		Observer:     ginadapter.Observe, // auth.* fields on the request's wide event
	})
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{
		Store:      store,
		LoginURL:   provider.LoginURL(),
		Refreshers: []session.Refresher{provider}, // refetches teams every minute
		Observer:   ginadapter.Observe,
	})
	if err != nil {
		return nil, err
	}

	engine := gin.New()
	engine.Use(gin.Recovery(), wideevent.Middleware(wideevent.WithPreEnricher(ginadapter.RedactQuery)))
	ginadapter.RegisterRoutes(engine, provider.Routes()) // on the engine root: GET /auth/github/{login,callback,logout}, POST /auth/github/refresh-teams
	engine.GET("/auth/me", ginadapter.Middleware(guard.RequireAPI()), gin.WrapH(auth.IdentityHandler()))
	api := engine.Group("/api", ginadapter.Middleware(guard.RequireAPI()))
	api.GET("/notes", listNotes)
	api.DELETE("/notes", ginadapter.Require(authorization.IsAdmin()), deleteNotes)
	engine.GET("/", ginadapter.Middleware(guard.RequireUI()), home)
	return engine, nil
}

func listNotes(ginContext *gin.Context) {
	identity := auth.IdentityFrom(ginContext.Request.Context()) // never nil behind the Guard
	ginContext.JSON(http.StatusOK, gin.H{"owner": identity.Username, "teams": identity.Teams, "notes": []string{}})
}

func deleteNotes(ginContext *gin.Context) {
	ginContext.Status(http.StatusNoContent)
}

func home(ginContext *gin.Context) {
	ginContext.String(http.StatusOK, "hello %s\n", auth.IdentityFrom(ginContext.Request.Context()).Username)
}
