package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/password"
)

// TestServer registers a user, logs in the administrator, uses the protected routes and logs out.
func TestServer(t *testing.T) {
	storage := password.NewMemoryStorage()
	administratorID, err := createUser(t.Context(), storage, "admin", "correct horse battery staple")
	require.NoError(t, err)
	handler, err := newServer(&serverOptions{EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), Storage: storage, AdministratorID: administratorID})
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler) // the session cookie is Secure
	t.Cleanup(server.Close)

	anonymous := newClient(t, server)
	require.Equal(t, http.StatusUnauthorized, send(t, anonymous, http.MethodGet, server.URL+"/api/notes", "").status)
	page := send(t, anonymous, http.MethodGet, server.URL+"/", "")
	require.Equal(t, "/login", page.url.Path, "RequireUI redirects to the login page")
	require.Equal(t, "/", page.url.Query().Get("return_to"))

	user := newClient(t, server)
	require.Equal(t, http.StatusCreated, send(t, user, http.MethodPost, server.URL+"/auth/password/register", `{"username":"ada","password":"ada's long passphrase"}`).status)
	require.Equal(t, http.StatusOK, send(t, user, http.MethodGet, server.URL+"/api/notes", "").status)
	require.Equal(t, http.StatusForbidden, send(t, user, http.MethodDelete, server.URL+"/api/notes", "").status)

	administrator := newClient(t, server)
	require.Equal(t, http.StatusOK, send(t, administrator, http.MethodPost, server.URL+"/auth/password/login", `{"identifier":"admin","password":"correct horse battery staple"}`).status)
	require.Equal(t, "hello admin\n", send(t, administrator, http.MethodGet, server.URL+"/", "").body)
	require.Equal(t, http.StatusNoContent, send(t, administrator, http.MethodDelete, server.URL+"/api/notes", "").status)
	require.Equal(t, http.StatusNoContent, send(t, administrator, http.MethodPost, server.URL+"/auth/password/logout", "").status)
	require.Equal(t, http.StatusUnauthorized, send(t, administrator, http.MethodGet, server.URL+"/api/notes", "").status)
}

func TestCreateUserRefusesAWeakPassword(t *testing.T) {
	storage := password.NewMemoryStorage()

	_, err := createUser(t.Context(), storage, "admin", "x")

	require.ErrorContains(t, err, "shorter than 12 characters")
	_, err = storage.GetUserByUsername(t.Context(), "admin")
	require.ErrorIs(t, err, password.ErrUserNotFound)
}

func TestHTTPServerHasTimeouts(t *testing.T) {
	server := newHTTPServer(":8080", http.NotFoundHandler())

	require.Positive(t, server.ReadHeaderTimeout)
	require.Positive(t, server.ReadTimeout)
	require.Positive(t, server.WriteTimeout)
	require.Positive(t, server.IdleTimeout)
	require.Positive(t, server.MaxHeaderBytes)
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

// send sends a request with a JSON body (none when empty) and returns what the test reads of the response.
func send(t *testing.T, client *http.Client, method, target, jsonBody string) reply {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(jsonBody))
	require.NoError(t, err)
	if jsonBody != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()
	content, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return reply{status: response.StatusCode, url: response.Request.URL, body: string(content)}
}
