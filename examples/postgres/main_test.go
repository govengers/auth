package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/postgrestest"
)

func TestMain(m *testing.M) { postgrestest.Main(m) }

var encryptionKey = []byte("0123456789abcdef0123456789abcdef")

// TestServer registers and logs in a user, issues a read-only key, uses it, and checks that a second replica
// on the same database knows the session and the key, and that a revoked key is refused at once.
func TestServer(t *testing.T) {
	pool := postgrestest.New(t, migrations...)
	first, err := newServer(&serverOptions{EncryptionKey: encryptionKey, Pool: pool})
	require.NoError(t, err)
	second, err := newServer(&serverOptions{EncryptionKey: encryptionKey, Pool: pool})
	require.NoError(t, err)
	replicaOne, replicaTwo := httptest.NewTLSServer(first.handler), httptest.NewTLSServer(second.handler)
	t.Cleanup(replicaOne.Close)
	t.Cleanup(replicaTwo.Close)
	browser := newClient(t, replicaOne)

	require.Equal(t, http.StatusCreated, send(t, browser, http.MethodPost, replicaOne.URL+"/auth/password/register", `{"username":"ada","password":"ada's long passphrase"}`).status)
	require.Equal(t, http.StatusOK, send(t, browser, http.MethodGet, replicaTwo.URL+"/api/tasks", "").status, "the other replica reads the session")
	issued := send(t, browser, http.MethodPost, replicaOne.URL+"/api/keys", `{"name":"ci","scopes":["tasks:read"]}`)
	require.Equal(t, http.StatusCreated, issued.status)
	var key keyBody
	require.NoError(t, json.Unmarshal([]byte(issued.body), &key))

	script := withKey(newClient(t, replicaTwo), key.Key)
	require.Equal(t, http.StatusOK, send(t, script, http.MethodGet, replicaTwo.URL+"/api/tasks", "").status)
	require.Equal(t, http.StatusForbidden, send(t, script, http.MethodPost, replicaTwo.URL+"/api/tasks", "").status, "the key is read-only")
	require.Equal(t, http.StatusCreated, send(t, browser, http.MethodPost, replicaOne.URL+"/api/tasks", "").status, "the session is not")
	require.Equal(t, http.StatusUnauthorized, send(t, script, http.MethodPost, replicaTwo.URL+"/api/keys", `{"name":"x","scopes":["*:write"]}`).status, "a key cannot issue keys")
	require.Contains(t, send(t, browser, http.MethodGet, replicaOne.URL+"/api/keys", "").body, key.ID.String())

	require.Equal(t, http.StatusNoContent, send(t, browser, http.MethodDelete, replicaOne.URL+"/api/keys/"+key.ID.String(), "").status)
	require.Equal(t, http.StatusUnauthorized, send(t, script, http.MethodGet, replicaTwo.URL+"/api/tasks", "").status)
	require.Equal(t, http.StatusNotFound, send(t, browser, http.MethodDelete, replicaOne.URL+"/api/keys/"+key.ID.String(), "").status)

	require.Equal(t, http.StatusNoContent, send(t, browser, http.MethodPost, replicaTwo.URL+"/auth/password/logout", "").status)
	require.Equal(t, http.StatusUnauthorized, send(t, browser, http.MethodGet, replicaOne.URL+"/api/tasks", "").status, "logged out on every replica")
	_, err = first.backend.Sweep(t.Context())
	require.NoError(t, err)
}

func TestMigrateIsIdempotent(t *testing.T) {
	pool := postgrestest.New(t)
	require.NoError(t, migrate(t.Context(), pool))
	require.NoError(t, migrate(t.Context(), pool))
}

// newClient returns a client of server with its own cookie jar, like one browser.
func newClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := *server.Client()
	client.Jar = jar
	return &client
}

type reply struct {
	status int
	body   string
}

// keyTransport presents an API key on every request, like a script.
type keyTransport struct {
	key  string
	next http.RoundTripper
}

func (k *keyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header.Set("Authorization", "Bearer "+k.key)
	return k.next.RoundTrip(request)
}

func withKey(client *http.Client, key string) *http.Client {
	client.Transport = &keyTransport{key: key, next: client.Transport}
	return client
}

// send sends a request with a JSON body (none when empty).
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
	return reply{status: response.StatusCode, body: string(content)}
}
