package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
	"github.com/govengers/auth/session"
)

const (
	testExternalURL = "https://app.example.com"
	testCookieName  = "auth_session"
)

var errBackendDown = errors.New("backend down")

// switchableBackend is a memory backend whose Put and Revoke can be made to fail.
type switchableBackend struct {
	*session.MemoryBackend
	failPut    atomic.Bool
	failRevoke atomic.Bool
}

func (b *switchableBackend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	if b.failPut.Load() {
		return errBackendDown
	}
	return b.MemoryBackend.Put(ctx, sessionID, key, value, ttl)
}

func (b *switchableBackend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	if b.failRevoke.Load() {
		return errBackendDown
	}
	return b.MemoryBackend.Revoke(ctx, sessionID, ttl)
}

// outcomeRecorder is an auth.Observer that keeps every outcome.
type outcomeRecorder struct {
	mutex    sync.Mutex
	outcomes []auth.Outcome
}

func (r *outcomeRecorder) observe(_ context.Context, outcome auth.Outcome) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.outcomes = append(r.outcomes, outcome)
}

// last returns the latest outcome; the test fails without one.
func (r *outcomeRecorder) last(t *testing.T) auth.Outcome {
	t.Helper()
	r.mutex.Lock()
	defer r.mutex.Unlock()
	require.NotEmpty(t, r.outcomes)
	return r.outcomes[len(r.outcomes)-1]
}

// testEnvironment is a provider wired to a fake GitHub and a memory session store.
type testEnvironment struct {
	fake     *fakeprovider.GitHubServer
	backend  *switchableBackend
	store    *session.Store
	provider *Provider
	outcomes *outcomeRecorder
	serveMux *http.ServeMux
}

func defaultTestTeams() []fakeprovider.GitHubTeam {
	return []fakeprovider.GitHubTeam{
		{Organization: "Acme", Slug: "Developers"},
		{Organization: "acme", Slug: "admins"},
		{Organization: "acme", Slug: "ops"},
		{Organization: "other", Slug: "unrelated"},
	}
}

// newTestEnvironment starts a fake GitHub with teams and builds a provider for it; configure may change
// the options before New.
func newTestEnvironment(t *testing.T, teams []fakeprovider.GitHubTeam, configure func(options *Options)) *testEnvironment {
	t.Helper()
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{
		User:  fakeprovider.GitHubUser{ID: 42, Login: "Ada", Name: "Ada Lovelace", Email: "ada@example.com", AvatarURL: "https://avatars.example.com/42"},
		Teams: teams,
	})
	memoryBackend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	backend := &switchableBackend{MemoryBackend: memoryBackend}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	outcomes := &outcomeRecorder{}
	options := testOptions(fake, store)
	options.Observer = outcomes.observe
	if configure != nil {
		configure(options)
	}
	provider, err := New(options)
	require.NoError(t, err)
	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes())
	return &testEnvironment{fake: fake, backend: backend, store: store, provider: provider, outcomes: outcomes, serveMux: serveMux}
}

func testOptions(fake *fakeprovider.GitHubServer, store *session.Store) *Options {
	return &Options{
		ClientID:      fake.ClientID(),
		ClientSecret:  fake.ClientSecret(),
		AuthorizeURL:  fake.AuthorizeURL(),
		TokenURL:      fake.TokenURL(),
		APIURL:        fake.APIURL(),
		ExternalURL:   testExternalURL,
		AllowedTeams:  []string{"acme/developers"},
		AdminTeams:    []string{"Acme/Admins"},
		RelevantTeams: []string{"acme/ops"},
		Sessions:      store,
	}
}

func newRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	return httptest.NewRequestWithContext(t.Context(), method, target, nil)
}

// serve answers request with the provider's routes.
func (e *testEnvironment) serve(request *http.Request) *httptest.ResponseRecorder {
	return serveRecorder(e.serveMux, request)
}

func serveRecorder(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// withSessionCookie adds the session cookie that response set to request, as a browser would.
func withSessionCookie(t *testing.T, request *http.Request, response *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	request.AddCookie(sessionCookie(t, response))
	return request
}

// sessionCookie returns the session cookie response set; the test fails without one.
func sessionCookie(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == testCookieName {
			return cookie
		}
	}
	require.Fail(t, "no session cookie set")
	return nil
}

// startLogin calls the login route and returns its response, whose Location points at the fake GitHub.
func (e *testEnvironment) startLogin(t *testing.T, returnTo string) *httptest.ResponseRecorder {
	t.Helper()
	target := testExternalURL + "/auth/github/login"
	if returnTo != "" {
		target += "?return_to=" + url.QueryEscape(returnTo)
	}
	response := e.serve(newRequest(t, http.MethodGet, target))
	require.Equal(t, http.StatusFound, response.Code)
	return response
}

// approve follows location to the fake GitHub's authorize endpoint and returns the callback URL it redirects to.
func approve(t *testing.T, location string) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, location, nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusFound, response.StatusCode)
	return response.Header.Get("Location")
}

// callback delivers callbackURL to the callback route with the login's session cookie.
func (e *testEnvironment) callback(t *testing.T, login *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder {
	t.Helper()
	return e.serve(withSessionCookie(t, newRequest(t, http.MethodGet, callbackURL), login))
}

// login runs the whole browser flow and returns the callback's response, which must succeed.
func (e *testEnvironment) login(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	login := e.startLogin(t, "")
	response := e.callback(t, login, approve(t, login.Header().Get("Location")))
	require.Equal(t, http.StatusFound, response.Code, response.Body.String())
	return response
}

// sessionOf opens the session whose cookie response set.
func (e *testEnvironment) sessionOf(t *testing.T, response *httptest.ResponseRecorder) session.Session {
	t.Helper()
	current, err := e.store.Open(withSessionCookie(t, newRequest(t, http.MethodGet, testExternalURL+"/"), response))
	require.NoError(t, err)
	return current
}

// identityOf returns the identity of the session whose cookie response set.
func (e *testEnvironment) identityOf(t *testing.T, response *httptest.ResponseRecorder) *auth.Identity {
	t.Helper()
	identity, err := e.sessionOf(t, response).Identity(t.Context())
	require.NoError(t, err)
	return identity
}
