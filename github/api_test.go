package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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

	account, err := provider.fetchUser(t.Context(), provider.apiClient(provider.upstream, &oauth2.Token{AccessToken: "gho_secret", TokenType: "bearer"}))

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

			_, err := provider.fetchUser(t.Context(), provider.apiClient(provider.upstream, &oauth2.Token{AccessToken: "gho_secret"}))

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

	_, err := provider.fetchUser(t.Context(), provider.apiClient(provider.upstream, &oauth2.Token{AccessToken: "gho_secret"}))

	require.ErrorContains(t, err, "decode /user")
}

func TestGetJSONFailsWhenGitHubIsUnreachable(t *testing.T) {
	_, apiURL := startAPIStub(t, http.StatusOK, `{}`)
	provider := providerForAPI(t, apiURL)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := provider.fetchTeams(cancelled, provider.apiClient(provider.upstream, &oauth2.Token{AccessToken: "gho_secret"}))

	require.ErrorContains(t, err, "GET /user/teams")
	require.ErrorIs(t, err, context.Canceled)
	require.NotContains(t, err.Error(), "per_page", "the request URL is reduced to its origin")
	var urlError *url.Error
	require.False(t, errors.As(err, &urlError), "net/http's error is not part of the API")
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
		t.Run(http.StatusText(status), func(t *testing.T) {
			_, apiURL := startAPIStub(t, status, ``)
			provider := providerForAPI(t, apiURL)

			err := provider.revokeToken(t.Context(), &oauth2.Token{AccessToken: "gho_secret"})

			require.ErrorContains(t, err, "revoke token")
			require.NotContains(t, err.Error(), "gho_secret")
		})
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
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	provider := providerForAPI(t, server.URL)

	require.ErrorContains(t, provider.revokeToken(t.Context(), &oauth2.Token{AccessToken: "gho_secret"}), "revoke token")
}

func TestExchangeKeepsGitHubTextOutOfErrors(t *testing.T) {
	const marker = "marker-secret alice@example.test"
	testCases := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantStatus  int
		wantText    string
	}{
		{
			name: "error answer with description", status: http.StatusOK, contentType: "application/json",
			body:       `{"error":"bad_verification_code","error_description":"` + marker + `","error_uri":"https://docs.example.com/` + marker + `"}`,
			wantStatus: http.StatusUnauthorized, wantText: "token endpoint answered HTTP 200 bad_verification_code",
		},
		{
			name: "malformed error code", status: http.StatusBadRequest, contentType: "application/json",
			body:       `{"error":"` + marker + `"}`,
			wantStatus: http.StatusUnauthorized, wantText: "token endpoint answered HTTP 400",
		},
		{
			name: "refusal with a non-JSON body", status: http.StatusUnauthorized, contentType: "text/html",
			body:       "<p>" + marker + "</p>",
			wantStatus: http.StatusUnauthorized, wantText: "token endpoint answered HTTP 401",
		},
		{
			name: "outage with a body", status: http.StatusBadGateway, contentType: "text/html",
			body:       "<p>" + marker + "</p>",
			wantStatus: http.StatusInternalServerError, wantText: "token endpoint answered HTTP 502",
		},
		{
			name: "malformed token response", status: http.StatusOK, contentType: "application/json",
			body:       `{"access_token":"present","expires_in":"` + marker + `"}`,
			wantStatus: http.StatusInternalServerError, wantText: "token endpoint answered an unreadable token response",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", testCase.contentType)
				writer.WriteHeader(testCase.status)
				// A write error means the client under test hung up; its own assertion reports that.
				_, _ = writer.Write([]byte(testCase.body))
			}))
			t.Cleanup(server.Close)
			options := validOptions(t)
			options.TokenURL = server.URL
			provider, err := New(options)
			require.NoError(t, err)

			_, err = provider.exchange(t.Context(), "the-code", "the-verifier")

			require.ErrorContains(t, err, testCase.wantText)
			status, _ := auth.ResponseFor(err)
			require.Equal(t, testCase.wantStatus, status)
			for _, secret := range []string{"marker-secret", "alice", "the-code", "the-verifier", "client-secret"} {
				require.NotContains(t, err.Error(), secret)
			}
		})
	}
}

func TestExchangeKeepsACancelledContextDetectable(t *testing.T) {
	options := validOptions(t)
	options.TokenURL = "http://127.0.0.1:1/token"
	provider, err := New(options)
	require.NoError(t, err)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = provider.exchange(cancelled, "the-code", "the-verifier")

	require.ErrorIs(t, err, context.Canceled)
}

// redirectToSink starts a sink and an endpoint that answers every request with a redirect of status to the
// sink; it returns the endpoint's URL and a function counting the sink's requests.
func redirectToSink(t *testing.T, status int) (string, func() int) {
	t.Helper()
	var reached atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	t.Cleanup(sink.Close)
	endpoint := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, sink.URL+"/token", status)
	}))
	t.Cleanup(endpoint.Close)
	return endpoint.URL, func() int { return int(reached.Load()) }
}

func TestExchangeAndRevocationFollowNoRedirect(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			endpoint, sinkRequests := redirectToSink(t, status)
			options := validOptions(t)
			options.TokenURL, options.APIURL = endpoint+"/login/oauth/access_token", endpoint
			provider, err := New(options)
			require.NoError(t, err)

			_, exchangeError := provider.exchange(t.Context(), "the-code", "the-verifier")
			revokeError := provider.revokeToken(t.Context(), &oauth2.Token{AccessToken: "gho_secret"})

			require.ErrorContains(t, exchangeError, "redirect refused")
			status, _ := auth.ResponseFor(exchangeError)
			require.Equal(t, http.StatusInternalServerError, status, "a redirecting token endpoint is an outage, not a refusal")
			require.ErrorContains(t, revokeError, "redirect refused")
			require.Zero(t, sinkRequests(), "the client secret, code and verifier never reach the redirect's target")
		})
	}
}
