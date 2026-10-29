package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
	"github.com/govengers/auth/oidc"
	"github.com/govengers/auth/session"
)

const (
	externalURL  = "https://app.example.com"
	clientID     = "app"
	clientSecret = "app-secret"
	providerName = "test"
	prefix       = "/auth/oidc/test"
)

func testUser() fakeprovider.OIDCUser {
	return fakeprovider.OIDCUser{
		Subject: "user-1", PreferredUsername: "ada", Name: "Ada Lovelace", Email: "ada@example.com", EmailVerified: true,
		Picture: "https://example.com/ada.png", SessionID: "idp-session-1",
		RealmRoles: []string{"admin"}, ClientRoles: []string{"editor"}, Groups: []string{"/staff"},
	}
}

// startIssuer starts a fake issuer for client "app" logging in testUser, changed by configure.
func startIssuer(t *testing.T, configure func(options *fakeprovider.OIDCOptions)) *fakeprovider.OIDCServer {
	t.Helper()
	options := fakeprovider.OIDCOptions{
		ClientID: clientID, ClientSecret: clientSecret, User: testUser(),
		RedirectURIs:           []string{externalURL + prefix + "/callback"},
		PostLogoutRedirectURIs: []string{externalURL + "/"},
	}
	if configure != nil {
		configure(&options)
	}
	return fakeprovider.StartOIDC(t, options)
}

func newStore(t *testing.T) *session.Store {
	t.Helper()
	backend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	return store
}

// outcomes records what a provider reports.
type outcomes struct {
	mutex    sync.Mutex
	recorded []auth.Outcome
}

func (o *outcomes) observe(_ context.Context, outcome auth.Outcome) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.recorded = append(o.recorded, outcome)
}

func (o *outcomes) last(t *testing.T) auth.Outcome {
	t.Helper()
	o.mutex.Lock()
	defer o.mutex.Unlock()
	require.NotEmpty(t, o.recorded)
	return o.recorded[len(o.recorded)-1]
}

// testApp is a provider mounted on a mux, with a Guard-protected /me and the outcomes it reported.
type testApp struct {
	provider *oidc.Provider
	store    *session.Store
	handler  http.Handler
	outcomes *outcomes
}

// newApp builds a provider "test" against issuer, changed by configure, on its own store.
func newApp(t *testing.T, issuer *fakeprovider.OIDCServer, configure func(options *oidc.Options)) *testApp {
	t.Helper()
	return newAppOn(t, newStore(t), issuer, configure)
}

func newAppOn(t *testing.T, store *session.Store, issuer *fakeprovider.OIDCServer, configure func(options *oidc.Options)) *testApp {
	t.Helper()
	recorded := &outcomes{}
	options := &oidc.Options{
		Name: providerName, Issuer: issuer.IssuerURL(), ClientID: clientID, ClientSecret: clientSecret,
		ExternalURL: externalURL, Sessions: store, Observer: recorded.observe,
	}
	if configure != nil {
		configure(options)
	}
	provider, err := oidc.New(t.Context(), options)
	require.NoError(t, err)
	return &testApp{provider: provider, store: store, handler: mount(t, store, provider), outcomes: recorded}
}

func mount(t *testing.T, store *session.Store, providers ...*oidc.Provider) http.Handler {
	t.Helper()
	guard, err := session.NewGuard(&session.GuardOptions{Store: store})
	require.NoError(t, err)
	mux := http.NewServeMux()
	for _, provider := range providers {
		auth.RegisterRoutes(mux, provider.Routes())
	}
	mux.Handle("GET /me", guard.RequireAPI()(auth.IdentityHandler()))
	return mux
}

// browser keeps cookies like a browser (Secure ones too: the app is reached through recorders) and
// returns every redirect to the test.
type browser struct {
	t       *testing.T
	cookies map[string]*http.Cookie
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	return &browser{t: t, cookies: map[string]*http.Cookie{}}
}

// app sends GET target (an absolute URL on externalURL or a path) to handler.
func (b *browser) app(handler http.Handler, target string, header http.Header) *httptest.ResponseRecorder {
	b.t.Helper()
	request := httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, strings.TrimPrefix(target, externalURL), nil)
	for name, values := range header {
		request.Header[name] = values
	}
	for _, cookie := range b.cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	for _, line := range recorder.Header().Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(line)
		require.NoError(b.t, err)
		if cookie.MaxAge < 0 {
			delete(b.cookies, cookie.Name)
			continue
		}
		b.cookies[cookie.Name] = cookie
	}
	return recorder
}

// issuer sends GET target to the fake issuer, requires a redirect and returns its location without
// following it.
func (b *browser) issuer(target string) string {
	b.t.Helper()
	request, err := http.NewRequestWithContext(b.t.Context(), http.MethodGet, target, nil)
	require.NoError(b.t, err)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	require.NoError(b.t, err)
	defer func() { _ = response.Body.Close() }() // only the status and Location are read
	require.Equal(b.t, http.StatusFound, response.StatusCode)
	return response.Header.Get("Location")
}

// toCallback walks login and IdP and returns the callback URL the IdP redirected to.
func (b *browser) toCallback(app *testApp, loginTarget string) string {
	b.t.Helper()
	login := b.app(app.handler, loginTarget, nil)
	require.Equal(b.t, http.StatusFound, login.Code, login.Body.String())
	callback := b.issuer(login.Header().Get("Location"))
	require.True(b.t, strings.HasPrefix(callback, externalURL+prefix+"/callback?"), callback)
	return callback
}

// signIn runs the whole login and returns the callback's response.
func (b *browser) signIn(app *testApp, loginTarget string) *httptest.ResponseRecorder {
	b.t.Helper()
	return b.app(app.handler, b.toCallback(app, loginTarget), nil)
}

// me returns the status of the Guard-protected /me.
func (b *browser) me(app *testApp) int {
	b.t.Helper()
	return b.app(app.handler, "/me", nil).Code
}

// sessionValue reads key from the browser's session in store.
func (b *browser) sessionValue(store *session.Store, key string) string {
	b.t.Helper()
	request := httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, "/", nil)
	for _, cookie := range b.cookies {
		request.AddCookie(cookie)
	}
	current, err := store.Open(request)
	require.NoError(b.t, err)
	value, found, err := current.Get(b.t.Context(), key)
	require.NoError(b.t, err)
	require.True(b.t, found, key)
	return string(value)
}

func queryOf(t *testing.T, location string) url.Values {
	t.Helper()
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	return parsed.Query()
}
