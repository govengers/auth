package github

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

func validOptions(t *testing.T) *Options {
	t.Helper()
	backend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	return &Options{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		ExternalURL:  "https://app.example.com/",
		AllowedTeams: []string{"acme/developers"},
		Sessions:     store,
	}
}

func TestNewRefusesInvalidOptions(t *testing.T) {
	testCases := []struct {
		name   string
		change func(options *Options)
	}{
		{name: "missing client ID", change: func(options *Options) { options.ClientID = "" }},
		{name: "missing client secret", change: func(options *Options) { options.ClientSecret = "" }},
		{name: "missing sessions", change: func(options *Options) { options.Sessions = nil }},
		{name: "missing external URL", change: func(options *Options) { options.ExternalURL = "" }},
		{name: "relative external URL", change: func(options *Options) { options.ExternalURL = "/app" }},
		{name: "external URL with query", change: func(options *Options) { options.ExternalURL = "https://app.example.com/?x=1" }},
		{name: "no allowed team", change: func(options *Options) { options.AllowedTeams = nil }},
		{name: "allowed team without slash", change: func(options *Options) { options.AllowedTeams = []string{"acme"} }},
		{name: "allowed team without slug", change: func(options *Options) { options.AllowedTeams = []string{"acme/"} }},
		{name: "allowed team without organization", change: func(options *Options) { options.AllowedTeams = []string{"/developers"} }},
		{name: "allowed team with two slashes", change: func(options *Options) { options.AllowedTeams = []string{"acme/developers/x"} }},
		{name: "allowed team with a space", change: func(options *Options) { options.AllowedTeams = []string{"acme/ developers"} }},
		{name: "allowed team with a tab", change: func(options *Options) { options.AllowedTeams = []string{"acme/develop\ters"} }},
		{name: "invalid admin team", change: func(options *Options) { options.AdminTeams = []string{"admins"} }},
		{name: "invalid relevant team", change: func(options *Options) { options.RelevantTeams = []string{"acme//ops"} }},
		{name: "plain http authorize URL", change: func(options *Options) { options.AuthorizeURL = "http://github.example.com/login/oauth/authorize" }},
		{name: "ftp token URL", change: func(options *Options) { options.TokenURL = "ftp://github.example.com/token" }},
		{name: "relative API URL", change: func(options *Options) { options.APIURL = "/api/v3" }},
		{name: "API URL with user info", change: func(options *Options) { options.APIURL = "https://user:secret@ghe.example.com/api/v3" }},
		{name: "plain http API URL on a lookalike host", change: func(options *Options) { options.APIURL = "http://127.0.0.1.example.com" }},
		{name: "path prefix with trailing slash", change: func(options *Options) { options.PathPrefix = "/auth/github/" }},
		{name: "path prefix without leading slash", change: func(options *Options) { options.PathPrefix = "auth/github" }},
		{name: "path prefix with a wildcard", change: func(options *Options) { options.PathPrefix = "/auth/{provider}" }},
		{name: "protocol-relative post logout URL", change: func(options *Options) { options.PostLogoutURL = "//evil.example.com" }},
		{name: "javascript post logout URL", change: func(options *Options) { options.PostLogoutURL = "javascript:alert(1)" }},
		{name: "protocol-relative error URL", change: func(options *Options) { options.ErrorURL = "//evil.example.com/error" }},
		{name: "post logout URL with fragment", change: func(options *Options) { options.PostLogoutURL = "/goodbye#now" }},
		{name: "error URL with fragment", change: func(options *Options) { options.ErrorURL = "https://app.example.com/#/error" }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := validOptions(t)
			testCase.change(options)
			provider, err := New(options)
			require.Error(t, err)
			require.Nil(t, provider)
		})
	}
	t.Run("nil options", func(t *testing.T) {
		_, err := New(nil)
		require.Error(t, err)
	})
}

func TestNewAcceptsLoopbackAndEnterpriseURLs(t *testing.T) {
	testCases := []struct {
		name   string
		change func(options *Options)
	}{
		{name: "http on 127.0.0.1", change: func(options *Options) { options.APIURL = "http://127.0.0.1:8080" }},
		{name: "http on 127.0.0.0/8", change: func(options *Options) { options.TokenURL = "http://127.1.2.3/token" }},
		{name: "http on localhost", change: func(options *Options) { options.AuthorizeURL = "http://localhost:9000/authorize" }},
		{name: "http on ::1", change: func(options *Options) { options.APIURL = "http://[::1]:8080" }},
		{name: "GitHub Enterprise", change: func(options *Options) { options.APIURL = "https://ghe.example.com/api/v3" }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := validOptions(t)
			testCase.change(options)
			_, err := New(options)
			require.NoError(t, err)
		})
	}
}

func TestNewMakesRelativeRedirectTargetsAbsolute(t *testing.T) {
	options := validOptions(t)
	options.PostLogoutURL = "/goodbye"
	options.ErrorURL = "/login?failed=1"

	provider, err := New(options)

	require.NoError(t, err)
	require.Equal(t, "https://app.example.com/goodbye", provider.options.PostLogoutURL)
	require.Equal(t, "https://app.example.com/login?failed=1", provider.options.ErrorURL)
	require.Equal(t, "/goodbye", options.PostLogoutURL, "the caller's options stay unchanged")
}

func TestNewAppliesDefaults(t *testing.T) {
	options := validOptions(t)
	options.APIURL = "https://ghe.example.com/api/v3/"

	provider, err := New(options)

	require.NoError(t, err)
	require.Equal(t, "github", provider.Name())
	require.Equal(t, "https://app.example.com/auth/github/login", provider.LoginURL())
	require.Equal(t, "https://app.example.com/", provider.options.PostLogoutURL)
	require.Equal(t, "https://ghe.example.com/api/v3", provider.options.APIURL)
	require.Equal(t, defaultAuthorizeURL, provider.oauth.Endpoint.AuthURL)
	require.Equal(t, defaultTokenURL, provider.oauth.Endpoint.TokenURL)
	require.Equal(t, "https://app.example.com/auth/github/callback", provider.oauth.RedirectURL)
	require.Equal(t, []string{"read:org"}, provider.oauth.Scopes)
	require.Equal(t, 10*time.Second, provider.options.HTTPClient.Timeout)
	var routes []string
	for _, route := range provider.Routes() {
		routes = append(routes, route.Method+" "+route.Path)
	}
	require.Equal(t, []string{
		"GET /auth/github/login", "GET /auth/github/callback", "GET /auth/github/logout", "POST /auth/github/refresh-teams",
	}, routes)
}

func TestNewUsesCustomPathPrefixAndScopes(t *testing.T) {
	options := validOptions(t)
	options.PathPrefix = "/login/github"
	options.Scopes = []string{"read:org", "user:email"}

	provider, err := New(options)

	require.NoError(t, err)
	require.Equal(t, "https://app.example.com/login/github/login", provider.LoginURL())
	require.Equal(t, "https://app.example.com/login/github/callback", provider.oauth.RedirectURL)
	require.Equal(t, []string{"read:org", "user:email"}, provider.oauth.Scopes)
}

func TestNewLeavesCallerOptionsUntouched(t *testing.T) {
	options := validOptions(t)
	options.AllowedTeams = []string{"Acme/Developers"}
	options.AdminTeams = []string{"Acme/Admins"}
	options.RelevantTeams = []string{"Acme/Ops"}
	options.Scopes = []string{"read:org"}
	before := *options

	provider, err := New(options)
	require.NoError(t, err)

	require.Equal(t, before, *options)
	require.Equal(t, []string{"Acme/Developers"}, options.AllowedTeams)
	require.Nil(t, options.HTTPClient)
	options.AllowedTeams[0] = "evil/team"
	options.AdminTeams[0] = "evil/admins"
	options.Scopes[0] = "admin:org"
	require.Equal(t, []string{"acme/developers"}, provider.options.AllowedTeams)
	require.Equal(t, []string{"acme/admins"}, provider.options.AdminTeams)
	require.Equal(t, []string{"acme/ops"}, provider.options.RelevantTeams)
	require.Equal(t, []string{"read:org"}, provider.oauth.Scopes)
}

func TestProviderIsARefresher(t *testing.T) {
	provider, err := New(validOptions(t))
	require.NoError(t, err)

	var refresher session.Refresher = provider

	require.Equal(t, "github", refresher.Name())
	guard, err := session.NewGuard(&session.GuardOptions{Store: provider.options.Sessions, LoginURL: provider.LoginURL(), Refreshers: []session.Refresher{provider}})
	require.NoError(t, err)
	require.NotNil(t, guard)
}

func TestRoutesAnswerOnlyTheirMethods(t *testing.T) {
	provider, err := New(validOptions(t))
	require.NoError(t, err)
	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes())

	for _, testCase := range []struct{ method, path string }{
		{http.MethodPost, "/auth/github/login"},
		{http.MethodGet, "/auth/github/refresh-teams"},
		{http.MethodPost, "/auth/github/logout"},
	} {
		response := serveRecorder(serveMux, newRequest(t, testCase.method, testCase.path))
		require.Equal(t, http.StatusMethodNotAllowed, response.Code, testCase.method+" "+testCase.path)
	}
}
