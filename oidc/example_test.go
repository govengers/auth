package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
	"github.com/govengers/auth/oidc"
	"github.com/govengers/auth/session"
)

// startExampleIssuer serves the test fake in place of Keycloak or Google; a real application passes its
// IdP's issuer URL instead.
func startExampleIssuer() (*httptest.Server, error) {
	server := httptest.NewUnstartedServer(nil)
	handler, err := fakeprovider.NewOIDCHandler(&fakeprovider.OIDCOptions{
		IssuerURL: "http://" + server.Listener.Addr().String(), ClientID: "app", ClientSecret: "app-secret",
	})
	if err != nil {
		server.Close()
		return nil, err
	}
	server.Config.Handler = handler
	server.Start()
	return server, nil
}

func ExampleNew() {
	issuer, err := startExampleIssuer()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer issuer.Close()
	backend, err := session.NewMemoryBackend(nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		fmt.Println(err)
		return
	}
	provider, err := oidc.New(context.Background(), &oidc.Options{
		Name:         "keycloak",
		Issuer:       issuer.URL, // e.g. https://sso.example.com/realms/staff
		ClientID:     "app",
		ClientSecret: "app-secret",
		ExternalURL:  "https://app.example.com", // register https://app.example.com/auth/oidc/keycloak/callback at the IdP
		Sessions:     store,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	guard, err := session.NewGuard(&session.GuardOptions{Store: store, LoginURL: provider.LoginURL()})
	if err != nil {
		fmt.Println(err)
		return
	}
	mux := http.NewServeMux()
	auth.RegisterRoutes(mux, provider.Routes())
	mux.Handle("GET /reports", guard.RequireUI()(auth.IdentityHandler()))

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/reports", nil))

	for _, route := range provider.Routes() {
		fmt.Println(route.Method, route.Path)
	}
	fmt.Println(recorder.Code, recorder.Header().Get("Location"))
	// Output:
	// GET /auth/oidc/keycloak/login
	// GET /auth/oidc/keycloak/callback
	// GET /auth/oidc/keycloak/logout
	// GET /auth/oidc/keycloak/frontchannel-logout
	// 302 https://app.example.com/auth/oidc/keycloak/login?return_to=%2Freports
}
