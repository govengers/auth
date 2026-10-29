//go:build e2e

// Command fakeissuer runs the fake OpenID Connect provider of the compose end-to-end stack: the same
// fakeprovider.OIDCHandler the unit and subprocess tests use, as a container.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/govengers/config/v2"

	"github.com/govengers/auth/internal/fakeprovider"
)

const shutdownTimeout = 5 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		return healthcheck()
	}
	var listenAddress string
	options := &fakeprovider.OIDCOptions{
		User: fakeprovider.OIDCUser{Subject: "alice-id", PreferredUsername: "alice", Name: "Alice", Email: "alice@example.com", EmailVerified: true},
	}
	err := config.LoadConfigWithOptions([]config.Value{
		config.String("LISTEN_ADDRESS").NotEmpty().Into(&listenAddress), // all interfaces: Docker forwards to the container address
		config.String("ISSUER_URL").NotEmpty().Into(&options.IssuerURL),
		config.String("CLIENT_ID").NotEmpty().Into(&options.ClientID),
		config.String("CLIENT_SECRET").NotEmpty().Sensitive().Into(&options.ClientSecret),
		config.StringArray("REDIRECT_URIS").NotEmpty().Into(&options.RedirectURIs),
		config.StringArray("POST_LOGOUT_REDIRECT_URIS").Default(nil).Into(&options.PostLogoutRedirectURIs),
	}, &config.LoadConfigOptions{DisableDotEnv: true})
	if err != nil {
		return err
	}
	issuer, err := fakeprovider.NewOIDCHandler(options)
	if err != nil {
		return err
	}
	return serve(listenAddress, issuer)
}

// serve runs until SIGTERM: docker compose stop sends it, and a process running as PID 1 ignores it
// unless it handles it.
func serve(listenAddress string, handler http.Handler) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Addr: listenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.ListenAndServe() }()

	select {
	case err := <-serveErrors:
		return err
	case <-ctx.Done():
	}
	shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	return server.Shutdown(shutdownContext)
}

// healthcheck is the container health probe: distroless has no shell or curl to run instead.
func healthcheck() error {
	target := "http://127.0.0.1" + os.Getenv("LISTEN_ADDRESS") + "/jwks"
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil) //nolint:gosec // G704: the URL is this container's own listen address
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request) //nolint:gosec // G704: the URL is this container's own listen address
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }() // read-only response
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s", response.Status)
	}
	return nil
}
