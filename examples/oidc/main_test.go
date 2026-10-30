package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeprovider"
	"github.com/govengers/auth/oidc/keycloak"
)

// TestServer logs in through a fake issuer, uses the protected routes and logs out, with and without the
// Keycloak enrichment.
func TestServer(t *testing.T) {
	tests := []struct {
		name       string
		keycloak   bool
		realmRoles []string
		wantDelete int
	}{
		{name: "token roles, admin", realmRoles: []string{"admin"}, wantDelete: http.StatusNoContent},
		{name: "keycloak roles, no admin", keycloak: true, wantDelete: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuerOptions := fakeprovider.OIDCOptions{
				ClientID: "app", ClientSecret: "app-secret",
				User: fakeprovider.OIDCUser{Subject: "user-1", PreferredUsername: "ada", RealmRoles: test.realmRoles},
			}
			if test.keycloak {
				issuerOptions.KeycloakRealm, issuerOptions.KeycloakClientID, issuerOptions.KeycloakClientSecret = "example", "app-admin", "service-secret"
			}
			issuer := fakeprovider.StartOIDC(t, issuerOptions)
			server := httptest.NewUnstartedServer(nil) // its address is the ExternalURL newServer needs
			t.Cleanup(server.Close)
			options := &serverOptions{
				EncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
				ExternalURL:   "https://" + server.Listener.Addr().String(),
				Issuer:        issuer.IssuerURL(),
				ClientID:      "app",
				ClientSecret:  "app-secret",
			}
			if test.keycloak {
				options.Keycloak = &keycloak.Options{URL: issuer.URL(), Realm: "example", ClientID: "app-admin", ClientSecret: "service-secret"}
			}
			handler, err := newServer(t.Context(), options)
			require.NoError(t, err)
			server.Config.Handler = handler
			server.StartTLS() // the session cookie is Secure

			browser := newClient(t, server)
			require.Equal(t, http.StatusUnauthorized, send(t, browser, http.MethodGet, server.URL+"/api/notes").status)
			require.Equal(t, "hello ada\n", send(t, browser, http.MethodGet, server.URL+"/").body) // RequireUI, login, IdP, callback, back to /
			require.Equal(t, http.StatusOK, send(t, browser, http.MethodGet, server.URL+"/api/notes").status)
			require.Equal(t, test.wantDelete, send(t, browser, http.MethodDelete, server.URL+"/api/notes").status)

			browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse } // the IdP would log in again
			logout := send(t, browser, http.MethodGet, server.URL+"/auth/oidc/sso/logout")
			require.Equal(t, http.StatusFound, logout.status, "redirect to the IdP's end-session endpoint")
			require.Equal(t, http.StatusUnauthorized, send(t, browser, http.MethodGet, server.URL+"/api/notes").status)
		})
	}
}

// newClient returns a client of server with its own cookie jar, like one browser.
func newClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := *server.Client() // a copy: server.Client returns the same client every time
	client.Jar = jar
	return &client
}

// reply is what a test reads of a response.
type reply struct {
	status int
	url    *url.URL // of the last request, after redirects
	body   string
}

// send sends a request and returns what the test reads of the response.
func send(t *testing.T, client *http.Client, method, target string) reply {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, target, nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()
	content, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return reply{status: response.StatusCode, url: response.Request.URL, body: string(content)}
}
