package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeprovider"
)

// TestServer logs in through a fake GitHub, uses the protected routes and logs out, as an admin team
// member and as a plain member.
func TestServer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name       string
		teams      []fakeprovider.GitHubTeam
		wantDelete int
	}{
		{name: "admin team", teams: []fakeprovider.GitHubTeam{{Organization: "acme", Slug: "developers"}, {Organization: "acme", Slug: "admins"}}, wantDelete: http.StatusNoContent},
		{name: "allowed team only", teams: []fakeprovider.GitHubTeam{{Organization: "acme", Slug: "developers"}}, wantDelete: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: test.teams})
			server := httptest.NewUnstartedServer(nil) // its address is the ExternalURL newServer needs
			t.Cleanup(server.Close)
			handler, err := newServer(&serverOptions{
				EncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
				ExternalURL:   "https://" + server.Listener.Addr().String(),
				ClientID:      fake.ClientID(),
				ClientSecret:  fake.ClientSecret(),
				AllowedTeams:  []string{"acme/developers"},
				AdminTeams:    []string{"acme/admins"},
				AuthorizeURL:  fake.AuthorizeURL(),
				TokenURL:      fake.TokenURL(),
				APIURL:        fake.APIURL(),
			})
			require.NoError(t, err)
			server.Config.Handler = handler
			server.StartTLS() // the session cookie is Secure

			browser := newClient(t, server)
			require.Equal(t, http.StatusUnauthorized, send(t, browser, http.MethodGet, server.URL+"/api/notes").status)
			require.Equal(t, "hello octocat\n", send(t, browser, http.MethodGet, server.URL+"/").body) // RequireUI, login, GitHub, callback, back to /
			require.Equal(t, http.StatusOK, send(t, browser, http.MethodGet, server.URL+"/api/notes").status)
			require.Equal(t, test.wantDelete, send(t, browser, http.MethodDelete, server.URL+"/api/notes").status)

			browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse } // / would log in again
			logout := send(t, browser, http.MethodGet, server.URL+"/auth/github/logout")
			require.Equal(t, http.StatusFound, logout.status)
			require.Equal(t, http.StatusUnauthorized, send(t, browser, http.MethodGet, server.URL+"/api/notes").status)
			require.Len(t, fake.RevokedTokens(), 1, "logout revokes the token at GitHub")
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
