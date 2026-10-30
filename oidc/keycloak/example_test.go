package keycloak_test

import (
	"context"
	"fmt"
	"net/http/httptest"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
	"github.com/govengers/auth/oidc/keycloak"
)

// startExampleKeycloak serves the test fake in place of Keycloak: realm "staff" with one user and a
// service account client "app-admin".
func startExampleKeycloak() (*httptest.Server, error) {
	server := httptest.NewUnstartedServer(nil)
	base := "http://" + server.Listener.Addr().String()
	handler, err := fakeprovider.NewOIDCHandler(&fakeprovider.OIDCOptions{
		IssuerURL: base + "/realms/staff", ClientID: "app", ClientSecret: "app-secret",
		KeycloakRealm: "staff", KeycloakClientID: "app-admin", KeycloakClientSecret: "service-secret",
		User: fakeprovider.OIDCUser{Subject: "user-1", RealmRoles: []string{"admin"}, Groups: []string{"/staff/scoring"}},
	})
	if err != nil {
		server.Close()
		return nil, err
	}
	server.Config.Handler = handler
	server.Start()
	return server, nil
}

func ExampleClient_Enrich() {
	server, err := startExampleKeycloak()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer server.Close()
	client, err := keycloak.New(&keycloak.Options{
		URL:                server.URL, // e.g. https://sso.example.com
		Realm:              "staff",
		ClientID:           "app-admin", // service account with the realm-management roles view-users, query-users and query-groups (README)
		ClientSecret:       "service-secret",
		RequiredRealmRoles: []string{"admin"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	// Usually wired as oidc.Options{OnLogin: client.Enrich}; the oidc provider calls it after the callback.
	enriched, err := client.Enrich(context.Background(), &auth.Identity{Provider: "keycloak", Subject: "user-1", Active: true})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(enriched.OIDCRoles, enriched.Groups)
	// Output: [admin] [/staff/scoring]
}
