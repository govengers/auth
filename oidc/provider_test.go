package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/oidc"
	"github.com/govengers/auth/session"
)

func TestNewValidatesOptions(t *testing.T) {
	issuer := startIssuer(t, nil)
	store := newStore(t)
	valid := func() *oidc.Options {
		return &oidc.Options{Name: "test", Issuer: issuer.IssuerURL(), ClientID: clientID, ClientSecret: clientSecret, ExternalURL: externalURL, Sessions: store}
	}
	testCases := []struct {
		name   string
		change func(options *oidc.Options)
	}{
		{name: "empty name", change: func(options *oidc.Options) { options.Name = "" }},
		{name: "upper-case name", change: func(options *oidc.Options) { options.Name = "Keycloak" }},
		{name: "name with a space", change: func(options *oidc.Options) { options.Name = "key cloak" }},
		{name: "name of 33 characters", change: func(options *oidc.Options) { options.Name = strings.Repeat("a", 33) }},
		{name: "reserved password", change: func(options *oidc.Options) { options.Name = "password" }},
		{name: "reserved github", change: func(options *oidc.Options) { options.Name = "github" }},
		{name: "reserved apikey", change: func(options *oidc.Options) { options.Name = "apikey" }},
		{name: "reserved session", change: func(options *oidc.Options) { options.Name = "session" }},
		{name: "reserved jwt", change: func(options *oidc.Options) { options.Name = "jwt" }},
		{name: "no client ID", change: func(options *oidc.Options) { options.ClientID = "" }},
		{name: "no client secret", change: func(options *oidc.Options) { options.ClientSecret = "" }},
		{name: "no sessions", change: func(options *oidc.Options) { options.Sessions = nil }},
		{name: "no issuer", change: func(options *oidc.Options) { options.Issuer = "" }},
		{name: "plain HTTP issuer", change: func(options *oidc.Options) { options.Issuer = "http://idp.example.com" }},
		{name: "issuer with user info", change: func(options *oidc.Options) { options.Issuer = "https://user:pass@idp.example.com" }},
		{name: "no external URL", change: func(options *oidc.Options) { options.ExternalURL = "" }},
		{name: "external URL with query", change: func(options *oidc.Options) { options.ExternalURL = externalURL + "?a=b" }},
		{name: "path prefix with trailing slash", change: func(options *oidc.Options) { options.PathPrefix = "/auth/" }},
		{name: "path prefix without leading slash", change: func(options *oidc.Options) { options.PathPrefix = "auth" }},
		{name: "path prefix with a pattern", change: func(options *oidc.Options) { options.PathPrefix = "/auth/{name}" }},
		{name: "protocol-relative post-logout URL", change: func(options *oidc.Options) { options.PostLogoutURL = "//evil.example/bye" }},
		{name: "post-logout URL with fragment", change: func(options *oidc.Options) { options.PostLogoutURL = "https://www.example.com/#/bye" }},
		{name: "protocol-relative error URL", change: func(options *oidc.Options) { options.ErrorURL = "//evil.example/login" }},
		{name: "script error URL", change: func(options *oidc.Options) { options.ErrorURL = "javascript:alert(1)" }},
		{name: "error URL with fragment", change: func(options *oidc.Options) { options.ErrorURL = "/login#failed" }},
		{name: "empty scope", change: func(options *oidc.Options) { options.Scopes = []string{"openid", ""} }},
		{name: "scope with a space", change: func(options *oidc.Options) { options.Scopes = []string{"openid email"} }},
		{name: "email domain with @", change: func(options *oidc.Options) { options.AllowedEmailDomains = []string{"@example.com"} }},
		{name: "empty email domain", change: func(options *oidc.Options) { options.AllowedEmailDomains = []string{""} }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := valid()
			testCase.change(options)

			_, err := oidc.New(t.Context(), options)

			require.Error(t, err)
			require.NotContains(t, err.Error(), clientSecret)
		})
	}
	_, err := oidc.New(t.Context(), nil)
	require.Error(t, err)
	_, err = oidc.New(t.Context(), valid())
	require.NoError(t, err)
}

func TestNewFailsWhenDiscoveryFails(t *testing.T) {
	issuer := startIssuer(t, nil)
	testCases := []struct {
		name      string
		issuer    string
		wantError string
	}{
		{name: "unreachable", issuer: "http://127.0.0.1:1", wantError: "discover issuer"},
		{name: "issuer mismatch", issuer: issuer.IssuerURL() + "/", wantError: "discover issuer"},
		{name: "no discovery document", issuer: issuer.IssuerURL() + "/nothing", wantError: "discover issuer"},
		{name: "plain HTTP authorization endpoint", issuer: serveDiscovery(t, "authorization_endpoint", "http://idp.example.com/authorize"), wantError: "authorization_endpoint"},
		{name: "plain HTTP token endpoint", issuer: serveDiscovery(t, "token_endpoint", "http://idp.example.com/token"), wantError: "token_endpoint"},
		{name: "no token endpoint", issuer: serveDiscovery(t, "token_endpoint", ""), wantError: "token_endpoint"},
		{name: "plain HTTP JWKS", issuer: serveDiscovery(t, "jwks_uri", "http://idp.example.com/jwks"), wantError: "jwks_uri"},
		{name: "plain HTTP end_session_endpoint", issuer: serveDiscovery(t, "end_session_endpoint", "http://idp.example.com/logout"), wantError: "end_session_endpoint"},
		{name: "relative end_session_endpoint", issuer: serveDiscovery(t, "end_session_endpoint", "/logout"), wantError: "end_session_endpoint"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := oidc.New(t.Context(), discoveryOptions(t, testCase.issuer))

			require.ErrorContains(t, err, `oidc provider "test"`)
			require.ErrorContains(t, err, testCase.wantError)
		})
	}
	_, err := oidc.New(t.Context(), discoveryOptions(t, serveDiscovery(t, "", "")))
	require.NoError(t, err, "the served document is valid without a change")
}

func discoveryOptions(t *testing.T, issuer string) *oidc.Options {
	t.Helper()
	return &oidc.Options{Name: "test", Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret, ExternalURL: externalURL, Sessions: newStore(t)}
}

// serveDiscovery serves a discovery document on loopback whose endpoints are the server's own, with
// field set to value unless field is "", and returns the issuer URL.
func serveDiscovery(t *testing.T, field, value string) string {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	issuer := "http://" + server.Listener.Addr().String()
	document := map[string]string{
		"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		"jwks_uri": issuer + "/jwks", "end_session_endpoint": issuer + "/logout",
	}
	if field != "" {
		document[field] = value
	}
	body, err := json.Marshal(document)
	require.NoError(t, err)
	server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(body) // the test reads the outcome from New, not from this write
	})
	server.Start()
	t.Cleanup(server.Close)
	return issuer
}

func TestNewDoesNotKeepTheCallersOptions(t *testing.T) {
	issuer := startIssuer(t, nil)
	options := &oidc.Options{
		Name: "test", Issuer: issuer.IssuerURL(), ClientID: clientID, ClientSecret: clientSecret, ExternalURL: externalURL + "/",
		Sessions: newStore(t), Scopes: []string{"email"}, AllowedEmailDomains: []string{"Example.com"},
	}
	before := *options
	before.Scopes, before.AllowedEmailDomains = slices.Clone(options.Scopes), slices.Clone(options.AllowedEmailDomains)
	provider, err := oidc.New(t.Context(), options)
	require.NoError(t, err)

	require.Equal(t, before.Scopes, options.Scopes)
	require.Equal(t, before.AllowedEmailDomains, options.AllowedEmailDomains)
	require.Equal(t, before.ExternalURL, options.ExternalURL)
	require.Empty(t, options.PathPrefix)
	options.Scopes[0] = "changed"
	login := newBrowser(t).app(mount(t, before.Sessions, provider), prefix+"/login", nil)
	require.Equal(t, "openid email", queryOf(t, login.Header().Get("Location")).Get("scope"))
}

func TestScopes(t *testing.T) {
	issuer := startIssuer(t, nil)
	testCases := []struct {
		name   string
		scopes []string
		want   string
	}{
		{name: "default", scopes: nil, want: "openid profile email"},
		{name: "openid added first", scopes: []string{"email", "groups"}, want: "openid email groups"},
		{name: "order kept, duplicates dropped", scopes: []string{"profile", "openid", "profile", "email"}, want: "profile openid email"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			app := newApp(t, issuer, func(options *oidc.Options) { options.Scopes = testCase.scopes })

			login := newBrowser(t).app(app.handler, prefix+"/login", nil)

			require.Equal(t, testCase.want, queryOf(t, login.Header().Get("Location")).Get("scope"))
		})
	}
}

func TestRoutesAndLoginURL(t *testing.T) {
	issuer := startIssuer(t, nil)
	testCases := []struct {
		name           string
		pathPrefix     string
		wantPathPrefix string
	}{
		{name: "default prefix", pathPrefix: "", wantPathPrefix: "/auth/oidc/test"},
		{name: "own prefix", pathPrefix: "/sso", wantPathPrefix: "/sso"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			app := newApp(t, issuer, func(options *oidc.Options) { options.PathPrefix = testCase.pathPrefix })

			routes := app.provider.Routes()

			paths := []string{}
			for _, route := range routes {
				require.Equal(t, http.MethodGet, route.Method)
				paths = append(paths, route.Path)
			}
			require.Equal(t, []string{
				testCase.wantPathPrefix + "/login", testCase.wantPathPrefix + "/callback",
				testCase.wantPathPrefix + "/logout", testCase.wantPathPrefix + "/frontchannel-logout",
			}, paths)
			require.Equal(t, externalURL+testCase.wantPathPrefix+"/login", app.provider.LoginURL())
			require.Equal(t, "test", app.provider.Name())
		})
	}
}

func TestLoginURLWorksAsTheGuardsLoginURL(t *testing.T) {
	app := newApp(t, startIssuer(t, nil), nil)
	guard, err := session.NewGuard(&session.GuardOptions{Store: app.store, LoginURL: app.provider.LoginURL()})
	require.NoError(t, err)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/reports?year=2026", nil)
	recorder := httptest.NewRecorder()

	guard.RequireUI()(auth.IdentityHandler()).ServeHTTP(recorder, request)

	require.Equal(t, http.StatusFound, recorder.Code)
	require.Equal(t, externalURL+prefix+"/login?return_to=%2Freports%3Fyear%3D2026", recorder.Header().Get("Location"))
}
