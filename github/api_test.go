package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
)

// apiStub is a GitHub API stand-in answering every request with status and body, recording the headers.
type apiStub struct {
	mutex   sync.Mutex
	headers []http.Header
	paths   []string
}

func startAPIStub(t *testing.T, status int, body string) (*apiStub, string) {
	t.Helper()
	stub := &apiStub{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		stub.mutex.Lock()
		stub.headers = append(stub.headers, request.Header.Clone())
		stub.paths = append(stub.paths, request.URL.RequestURI())
		stub.mutex.Unlock()
		writer.WriteHeader(status)
		// A write error means the client under test hung up; its own assertion reports that.
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return stub, server.URL
}

func providerForAPI(t *testing.T, apiURL string) *Provider {
	t.Helper()
	options := validOptions(t)
	options.APIURL = apiURL
	provider, err := New(options)
	require.NoError(t, err)
	return provider
}

func TestGetJSONSendsGitHubHeadersAndTheToken(t *testing.T) {
	stub, apiURL := startAPIStub(t, http.StatusOK, `{"id":7,"login":"octocat"}`)
	provider := providerForAPI(t, apiURL+"/")

	account, err := provider.fetchUser(t.Context(), provider.apiClient(&oauth2.Token{AccessToken: "gho_secret", TokenType: "bearer"}))

	require.NoError(t, err)
	require.Equal(t, user{ID: 7, Login: "octocat"}, account)
	require.Equal(t, []string{"/user"}, stub.paths)
	require.Equal(t, "application/vnd.github+json", stub.headers[0].Get("Accept"))
	require.Equal(t, "2022-11-28", stub.headers[0].Get("X-GitHub-Api-Version"))
	require.Equal(t, "Bearer gho_secret", stub.headers[0].Get("Authorization"))
}

func TestGetJSONFailures(t *testing.T) {
	testCases := []struct {
		name                string
		status              int
		body                string
		wantUnauthenticated bool
	}{
		{name: "401 is unauthenticated", status: http.StatusUnauthorized, body: `{"message":"Bad credentials"}`, wantUnauthenticated: true},
		{name: "403 is a plain error", status: http.StatusForbidden, body: `{"message":"rate limited"}`},
		{name: "500 is a plain error", status: http.StatusInternalServerError, body: ``},
		{name: "invalid JSON", status: http.StatusOK, body: `{"id":`},
		{name: "user without id", status: http.StatusOK, body: `{"login":"octocat"}`},
		{name: "user without login", status: http.StatusOK, body: `{"id":7}`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, apiURL := startAPIStub(t, testCase.status, testCase.body)
			provider := providerForAPI(t, apiURL)

			_, err := provider.fetchUser(t.Context(), provider.apiClient(&oauth2.Token{AccessToken: "gho_secret"}))

			require.Error(t, err)
			require.Equal(t, testCase.wantUnauthenticated, isRefusal(err))
			require.NotContains(t, err.Error(), "gho_secret")
		})
	}
}

func isRefusal(err error) bool {
	status, _ := auth.ResponseFor(err)
	return status == http.StatusUnauthorized
}

func TestGetJSONReadsAtMostTenMebibytes(t *testing.T) {
	_, apiURL := startAPIStub(t, http.StatusOK, `{"login":"`+strings.Repeat("a", maximumResponseBytes)+`","id":7}`)
	provider := providerForAPI(t, apiURL)

	_, err := provider.fetchUser(t.Context(), provider.apiClient(&oauth2.Token{AccessToken: "gho_secret"}))

	require.ErrorContains(t, err, "decode /user")
}

func TestGetJSONFailsWhenGitHubIsUnreachable(t *testing.T) {
	_, apiURL := startAPIStub(t, http.StatusOK, `{}`)
	provider := providerForAPI(t, apiURL)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := provider.fetchTeams(cancelled, provider.apiClient(&oauth2.Token{AccessToken: "gho_secret"}))

	require.ErrorContains(t, err, "GET /user/teams")
}

func TestFetchTeamsStopsAfterFiftyPages(t *testing.T) {
	teams := make([]fakeprovider.GitHubTeam, 0, (maximumTeamPages+1)*teamsPageSize)
	for range cap(teams) {
		teams = append(teams, fakeprovider.GitHubTeam{Organization: "Big", Slug: "Team"})
	}
	environment := newTestEnvironment(t, teams, nil)
	login := environment.startLogin(t, "")
	require.Equal(t, http.StatusForbidden, environment.callback(t, login, approve(t, login.Header().Get("Location"))).Code)

	require.Equal(t, maximumTeamPages, environment.fake.Calls(fakeprovider.GitHubEndpointTeams))
}

func TestRevokeTokenFailures(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusBadGateway} {
		_, apiURL := startAPIStub(t, status, ``)
		provider := providerForAPI(t, apiURL)

		err := provider.revokeToken(t.Context(), &oauth2.Token{AccessToken: "gho_secret"})

		require.ErrorContains(t, err, "revoke token")
		require.NotContains(t, err.Error(), "gho_secret")
	}
}

func TestRevokeTokenSendsTheAppCredentials(t *testing.T) {
	stub, apiURL := startAPIStub(t, http.StatusNoContent, ``)
	provider := providerForAPI(t, apiURL)

	require.NoError(t, provider.revokeToken(t.Context(), &oauth2.Token{AccessToken: "gho_secret"}))

	require.Equal(t, []string{"/applications/client-id/token"}, stub.paths)
	request := &http.Request{Header: stub.headers[0]}
	clientID, clientSecret, found := request.BasicAuth()
	require.True(t, found)
	require.Equal(t, "client-id", clientID)
	require.Equal(t, "client-secret", clientSecret)
	require.Equal(t, "application/json", stub.headers[0].Get("Content-Type"))
}

func TestRevokeTokenFailsWhenGitHubIsUnreachable(t *testing.T) {
	_, apiURL := startAPIStub(t, http.StatusNoContent, ``)
	options := validOptions(t)
	options.APIURL = apiURL
	options.HTTPClient = &http.Client{Transport: unreachableTransport{}}
	provider, err := New(options)
	require.NoError(t, err)

	require.ErrorContains(t, provider.revokeToken(t.Context(), &oauth2.Token{AccessToken: "gho_secret"}), "revoke token")
}

var errUnreachable = errors.New("unreachable")

type unreachableTransport struct{}

func (unreachableTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errUnreachable
}
