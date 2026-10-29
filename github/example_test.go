package github_test

import (
	"fmt"
	"net/http"

	"github.com/govengers/auth"
	"github.com/govengers/auth/github"
	"github.com/govengers/auth/session"
)

// Example wires the GitHub provider into a server: its routes, a Guard that sends unauthenticated
// browsers to the GitHub login and refreshes teams every minute, and an application route behind it.
func Example() {
	backend, err := session.NewMemoryBackend(nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	key, err := session.ParseKey("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") // from configuration in production
	if err != nil {
		fmt.Println(err)
		return
	}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key})
	if err != nil {
		fmt.Println(err)
		return
	}
	provider, err := github.New(&github.Options{
		ClientID:      "Iv1.0123456789abcdef",
		ClientSecret:  "from-configuration",
		ExternalURL:   "https://app.example.com",
		AllowedTeams:  []string{"acme/developers"},
		AdminTeams:    []string{"acme/admins"},
		RelevantTeams: []string{"acme/ops"},
		Sessions:      store,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	guard, err := session.NewGuard(&session.GuardOptions{
		Store:      store,
		LoginURL:   provider.LoginURL(),
		Refreshers: []session.Refresher{provider},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes())
	serveMux.Handle("GET /auth/me", guard.RequireAPI()(auth.IdentityHandler()))
	serveMux.Handle("/", guard.RequireUI()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := auth.IdentityFrom(request.Context())
		fmt.Fprintf(writer, "hello %s, teams %v", identity.Username, identity.Teams)
	})))

	for _, route := range provider.Routes() {
		fmt.Println(route.Method, route.Path)
	}
	fmt.Println(provider.LoginURL())
	// Output:
	// GET /auth/github/login
	// GET /auth/github/callback
	// GET /auth/github/logout
	// POST /auth/github/refresh-teams
	// https://app.example.com/auth/github/login
}

// ExampleProvider_HTTPClient calls the GitHub API with the session's token from an application handler.
func ExampleProvider_HTTPClient() {
	var (
		store    *session.Store   // the store the provider was built with
		provider *github.Provider // from github.New
	)
	repositories := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current, err := store.Open(request)
		if err != nil {
			auth.WriteError(writer, err)
			return
		}
		client, err := provider.HTTPClient(request.Context(), current)
		if err != nil {
			auth.WriteError(writer, err)
			return
		}
		apiRequest, err := http.NewRequestWithContext(request.Context(), http.MethodGet, "https://api.github.com/user/repos", nil)
		if err != nil {
			auth.WriteError(writer, err)
			return
		}
		response, err := client.Do(apiRequest)
		if err != nil {
			auth.WriteError(writer, err)
			return
		}
		defer response.Body.Close()
		writer.WriteHeader(response.StatusCode)
	})
	_ = repositories
}
