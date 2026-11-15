package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

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
	require.NoError(t, migrate(t.Context(), pool, migrations))
	require.NoError(t, migrate(t.Context(), pool, migrations))
}

// A start that fails halfway through the migrations leaves none applied, so the next start applies all.
func TestMigrateAppliesAllOrNone(t *testing.T) {
	pool := postgrestest.New(t)
	require.ErrorContains(t, migrate(t.Context(), pool, []string{migrations[0], "SELECT broken"}), "migrate")
	var applied bool
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('govengers_auth_sessions') IS NOT NULL`).Scan(&applied))
	require.False(t, applied, "the first migration was rolled back")

	require.NoError(t, migrate(t.Context(), pool, migrations))
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass('govengers_auth_api_keys') IS NOT NULL`).Scan(&applied))
	require.True(t, applied)
}

// The key issuing route accepts JSON only: a cross-origin form or text/plain fetch carrying the session
// cookie needs no CORS preflight and must not issue a key.
func TestIssueRefusesARequestThatIsNotJSON(t *testing.T) {
	pool := postgrestest.New(t, migrations...)
	server, err := newServer(&serverOptions{EncryptionKey: encryptionKey, Pool: pool})
	require.NoError(t, err)
	replica := httptest.NewTLSServer(server.handler)
	t.Cleanup(replica.Close)
	browser := newClient(t, replica)
	require.Equal(t, http.StatusCreated, send(t, browser, http.MethodPost, replica.URL+"/auth/password/register", `{"username":"ada","password":"ada's long passphrase"}`).status)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, replica.URL+"/api/keys", strings.NewReader(`{"name":"injected","scopes":["*:write"]}`))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "text/plain")
	response, err := browser.Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())

	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.Equal(t, "[]\n", send(t, browser, http.MethodGet, replica.URL+"/api/keys", "").body, "no key was issued")
}

func TestRecoveringTurnsAPanicIntoAnError(t *testing.T) {
	err := recovering(func() error { panic("sweep failed") })()
	require.ErrorContains(t, err, "panic: sweep failed")
	require.NoError(t, recovering(func() error { return nil })())
}

func TestServeStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	group, groupContext := errgroup.WithContext(ctx)
	serve(groupContext, group, newHTTPServer("127.0.0.1:0", http.NotFoundHandler()))
	cancel()
	require.NoError(t, group.Wait())
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
