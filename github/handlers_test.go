package github

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
)

func TestLoginRedirectsToGitHubWithPKCE(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)

	response := environment.startLogin(t, "/dashboard")

	location, err := url.Parse(response.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, environment.fake.AuthorizeURL(), location.Scheme+"://"+location.Host+location.Path)
	query := location.Query()
	require.Equal(t, environment.fake.ClientID(), query.Get("client_id"))
	require.Equal(t, testExternalURL+"/auth/github/callback", query.Get("redirect_uri"))
	require.Equal(t, "read:org", query.Get("scope"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(t, query.Get("code_challenge"))
	require.NotEmpty(t, query.Get("state"))
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.NotEmpty(t, sessionCookie(t, response).Value)
	outcome := environment.outcomes.last(t)
	require.Equal(t, auth.Outcome{Provider: "github", Action: auth.ActionLogin, Result: auth.ResultSuccess}, outcome)
}

func TestLoginFailsWhenTheSessionCannotBeStored(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	environment.backend.failPut.Store(true)

	response := environment.serve(newRequest(t, http.MethodGet, testExternalURL+"/auth/github/login"))

	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.JSONEq(t, `{"code":"internal","message":"internal error"}`, response.Body.String())
	outcome := environment.outcomes.last(t)
	require.Equal(t, auth.ResultError, outcome.Result)
	require.ErrorIs(t, outcome.Err, errBackendDown)
	require.ErrorContains(t, outcome.Err, "github: begin login: ")
}

func TestCallbackStartsTheSession(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.startLogin(t, "/dashboard?tab=2")

	response := environment.callback(t, login, approve(t, login.Header().Get("Location")))

	require.Equal(t, http.StatusFound, response.Code, response.Body.String())
	require.Equal(t, testExternalURL+"/dashboard?tab=2", response.Header().Get("Location"))
	require.NotEqual(t, sessionCookie(t, login).Value, sessionCookie(t, response).Value, "the session ID rotates after authentication")
	identity := environment.identityOf(t, response)
	require.Equal(t, &auth.Identity{
		Provider: "github",
		Subject:  "42",
		Username: "Ada",
		Name:     "Ada Lovelace",
		Email:    "ada@example.com",
		Picture:  "https://avatars.example.com/42",
		Active:   true,
		Roles:    []string{auth.RoleAdmin},
		Teams:    []string{"acme/admins", "acme/developers", "acme/ops"},
	}, identity)
	token, err := sessionToken(t.Context(), environment.sessionOf(t, response))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(token.AccessToken, "gho_"))
	outcome := environment.outcomes.last(t)
	require.Equal(t, auth.Outcome{Provider: "github", Action: auth.ActionCallback, Result: auth.ResultSuccess, Identity: identity}, outcome)
}

func TestCallbackDefaultsToTheRootPath(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)

	for _, returnTo := range []string{"", "//evil.example.com", "https://evil.example.com/", "/\\evil"} {
		login := environment.startLogin(t, returnTo)
		response := environment.callback(t, login, approve(t, login.Header().Get("Location")))
		require.Equal(t, testExternalURL+"/", response.Header().Get("Location"), returnTo)
	}
}

func TestCallbackReadsEveryTeamPage(t *testing.T) {
	teams := make([]fakeprovider.GitHubTeam, 0, 251)
	for index := range 250 {
		teams = append(teams, fakeprovider.GitHubTeam{Organization: "big", Slug: fmt.Sprintf("team-%d", index)})
	}
	teams = append(teams, fakeprovider.GitHubTeam{Organization: "acme", Slug: "developers"})
	environment := newTestEnvironment(t, teams, nil)

	response := environment.login(t)

	require.Equal(t, []string{"acme/developers"}, environment.identityOf(t, response).Teams)
	require.Equal(t, 3, environment.fake.Calls(fakeprovider.GitHubEndpointTeams))
}

func TestCallbackRefusesUsersOutsideTheAllowedTeams(t *testing.T) {
	testCases := []struct {
		name  string
		teams []fakeprovider.GitHubTeam
	}{
		{name: "no team", teams: nil},
		{name: "only unrelated teams", teams: []fakeprovider.GitHubTeam{{Organization: "other", Slug: "developers"}}},
		{name: "admin team without allowed team", teams: []fakeprovider.GitHubTeam{{Organization: "acme", Slug: "admins"}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testCase.teams, nil)
			login := environment.startLogin(t, "")

			response := environment.callback(t, login, approve(t, login.Header().Get("Location")))

			require.Equal(t, http.StatusForbidden, response.Code)
			require.JSONEq(t, `{"code":"forbidden","message":"access denied"}`, response.Body.String())
			require.Empty(t, response.Result().Cookies(), "no session is started")
			_, err := environment.sessionOf(t, login).Identity(t.Context())
			require.ErrorIs(t, err, auth.ErrUnauthenticated)
			outcome := environment.outcomes.last(t)
			require.Equal(t, auth.ResultDenied, outcome.Result)
			require.ErrorIs(t, outcome.Err, auth.ErrForbidden)
			require.Equal(t, "42", outcome.Identity.Subject)
		})
	}
}

func TestCallbackRefusals(t *testing.T) {
	testCases := []struct {
		name       string
		prepare    func(environment *testEnvironment)
		callback   func(t *testing.T, environment *testEnvironment, login *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder
		wantStatus int
		wantCode   string
		wantResult auth.Result
	}{
		{
			name:       "state mismatch",
			callback:   withQuery("state", "forged"),
			wantStatus: http.StatusBadRequest, wantCode: "state_mismatch", wantResult: auth.ResultDenied,
		},
		{
			name: "no session cookie",
			callback: func(t *testing.T, environment *testEnvironment, _ *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder {
				t.Helper()
				return environment.serve(newRequest(t, http.MethodGet, callbackURL))
			},
			wantStatus: http.StatusBadRequest, wantCode: "login_expired", wantResult: auth.ResultDenied,
		},
		{
			name: "replayed callback",
			callback: func(t *testing.T, environment *testEnvironment, login *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder {
				t.Helper()
				require.Equal(t, http.StatusFound, environment.callback(t, login, callbackURL).Code)
				return environment.callback(t, login, callbackURL)
			},
			wantStatus: http.StatusBadRequest, wantCode: "login_expired", wantResult: auth.ResultDenied,
		},
		{
			name:       "user declined at GitHub",
			prepare:    failing(fakeprovider.GitHubEndpointAuthorize, http.StatusForbidden),
			wantStatus: http.StatusUnauthorized, wantCode: "login_denied", wantResult: auth.ResultDenied,
		},
		{
			name:       "code rejected by GitHub",
			callback:   withQuery("code", "unknown-code"),
			wantStatus: http.StatusUnauthorized, wantCode: "login_failed", wantResult: auth.ResultDenied,
		},
		{
			name:       "token endpoint down",
			prepare:    failing(fakeprovider.GitHubEndpointToken, http.StatusBadGateway),
			wantStatus: http.StatusInternalServerError, wantCode: "internal", wantResult: auth.ResultError,
		},
		{
			name:       "user endpoint fails",
			prepare:    failing(fakeprovider.GitHubEndpointUser, http.StatusInternalServerError),
			wantStatus: http.StatusInternalServerError, wantCode: "internal", wantResult: auth.ResultError,
		},
		{
			name:       "user endpoint rejects the token",
			prepare:    failing(fakeprovider.GitHubEndpointUser, http.StatusUnauthorized),
			wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated", wantResult: auth.ResultDenied,
		},
		{
			name:       "teams endpoint fails",
			prepare:    failing(fakeprovider.GitHubEndpointTeams, http.StatusBadGateway),
			wantStatus: http.StatusInternalServerError, wantCode: "internal", wantResult: auth.ResultError,
		},
		{
			name:       "session rotation fails",
			callback:   failingRevokeCallback,
			wantStatus: http.StatusInternalServerError, wantCode: "internal", wantResult: auth.ResultError,
		},
		{
			name:       "session store fails",
			callback:   failingPutCallback,
			wantStatus: http.StatusInternalServerError, wantCode: "internal", wantResult: auth.ResultError,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			environment := newTestEnvironment(t, defaultTestTeams(), nil)
			if testCase.prepare != nil {
				testCase.prepare(environment)
			}
			deliver := testCase.callback
			if deliver == nil {
				deliver = deliverCallback
			}
			login := environment.startLogin(t, "")

			response := deliver(t, environment, login, approve(t, login.Header().Get("Location")))

			require.Equal(t, testCase.wantStatus, response.Code, response.Body.String())
			var body auth.ErrorResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, testCase.wantCode, body.Code)
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			outcome := environment.outcomes.last(t)
			require.Equal(t, auth.ActionCallback, outcome.Action)
			require.Equal(t, testCase.wantResult, outcome.Result)
			require.Error(t, outcome.Err)
		})
	}
}

// failing makes endpoint of the fake GitHub answer status.
func failing(endpoint fakeprovider.GitHubEndpoint, status int) func(environment *testEnvironment) {
	return func(environment *testEnvironment) { environment.fake.FailWith(endpoint, status) }
}

func deliverCallback(t *testing.T, environment *testEnvironment, login *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder {
	t.Helper()
	return environment.callback(t, login, callbackURL)
}

func failingPutCallback(t *testing.T, environment *testEnvironment, login *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder {
	t.Helper()
	environment.backend.failPut.Store(true)
	return environment.callback(t, login, callbackURL)
}

func failingRevokeCallback(t *testing.T, environment *testEnvironment, login *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder {
	t.Helper()
	environment.backend.failRevoke.Store(true)
	return environment.callback(t, login, callbackURL)
}

// withQuery delivers the callback with one query parameter replaced.
func withQuery(name, value string) func(t *testing.T, environment *testEnvironment, login *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder {
	return func(t *testing.T, environment *testEnvironment, login *httptest.ResponseRecorder, callbackURL string) *httptest.ResponseRecorder {
		t.Helper()
		parsed, err := url.Parse(callbackURL)
		require.NoError(t, err)
		query := parsed.Query()
		query.Set(name, value)
		parsed.RawQuery = query.Encode()
		return environment.callback(t, login, parsed.String())
	}
}

func TestCallbackRefusesAWrongPKCEVerifier(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.startLogin(t, "")
	location, err := url.Parse(login.Header().Get("Location"))
	require.NoError(t, err)
	query := location.Query()
	otherVerifier := sha256.Sum256([]byte("another login's verifier"))
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(otherVerifier[:]))
	location.RawQuery = query.Encode()

	response := environment.callback(t, login, approve(t, location.String()))

	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.JSONEq(t, `{"code":"login_failed","message":"authentication required"}`, response.Body.String())
}

func TestCallbackRefusesACodeIssuedForAnotherRedirectURI(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.startLogin(t, "")
	location, err := url.Parse(login.Header().Get("Location"))
	require.NoError(t, err)
	query := location.Query()
	query.Set("redirect_uri", "https://other.example.com/callback")
	location.RawQuery = query.Encode()
	otherCallback, err := url.Parse(approve(t, location.String()))
	require.NoError(t, err)
	require.Equal(t, "other.example.com", otherCallback.Host)

	response := environment.callback(t, login, testExternalURL+"/auth/github/callback?"+otherCallback.RawQuery)

	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.JSONEq(t, `{"code":"login_failed","message":"authentication required"}`, response.Body.String())
}

func TestCallbackRedirectsFailuresToTheErrorURL(t *testing.T) {
	testCases := []struct {
		name       string
		teams      []fakeprovider.GitHubTeam
		prepare    func(environment *testEnvironment)
		wantCode   string
		wantResult auth.Result
	}{
		{name: "refusal", wantCode: "forbidden", wantResult: auth.ResultDenied},
		{
			name: "GitHub failure", teams: defaultTestTeams(),
			prepare:  failing(fakeprovider.GitHubEndpointUser, http.StatusInternalServerError),
			wantCode: "internal", wantResult: auth.ResultError,
		},
		{
			name: "session rotation fails", teams: defaultTestTeams(),
			prepare:  func(environment *testEnvironment) { environment.backend.failRevoke.Store(true) },
			wantCode: "internal", wantResult: auth.ResultError,
		},
		{
			name: "session store fails", teams: defaultTestTeams(),
			prepare:  func(environment *testEnvironment) { environment.backend.failPut.Store(true) },
			wantCode: "internal", wantResult: auth.ResultError,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testCase.teams, func(options *Options) { options.ErrorURL = "/login?source=github" })
			login := environment.startLogin(t, "")
			if testCase.prepare != nil {
				testCase.prepare(environment)
			}

			response := environment.callback(t, login, approve(t, login.Header().Get("Location")))

			require.Equal(t, http.StatusFound, response.Code, response.Body.String())
			require.Equal(t, testExternalURL+"/login?source=github&code="+testCase.wantCode, response.Header().Get("Location"))
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			require.Len(t, environment.outcomes.outcomes, 2, "one login and one callback outcome")
			outcome := environment.outcomes.last(t)
			require.Equal(t, auth.ActionCallback, outcome.Action)
			require.Equal(t, testCase.wantResult, outcome.Result)
			require.Error(t, outcome.Err)
		})
	}
}

func TestCallbackRunsOnLogin(t *testing.T) {
	var received *auth.Identity
	environment := newTestEnvironment(t, defaultTestTeams(), func(options *Options) {
		options.OnLogin = func(_ context.Context, identity *auth.Identity) (*auth.Identity, error) {
			received = identity.Clone()
			mapped := identity.Clone()
			mapped.Roles = append(mapped.Roles, "editor")
			mapped.Data = map[string]any{"plan": "pro"}
			return mapped, nil
		}
	})

	response := environment.login(t)

	require.Equal(t, []string{"acme/admins", "acme/developers", "acme/ops"}, received.Teams)
	identity := environment.identityOf(t, response)
	require.Equal(t, []string{auth.RoleAdmin, "editor"}, identity.Roles)
	require.Equal(t, map[string]any{"plan": "pro"}, identity.Data)
}

func TestCallbackOnLoginRefusals(t *testing.T) {
	testCases := []struct {
		name       string
		hook       auth.Hook
		wantStatus int
	}{
		{name: "refusal", hook: func(context.Context, *auth.Identity) (*auth.Identity, error) {
			return nil, &auth.Error{Kind: auth.ErrForbidden, Reason: "suspended"}
		}, wantStatus: http.StatusForbidden},
		{name: "failure", hook: func(context.Context, *auth.Identity) (*auth.Identity, error) {
			return nil, errors.New("database down")
		}, wantStatus: http.StatusInternalServerError},
		{name: "no identity", hook: func(context.Context, *auth.Identity) (*auth.Identity, error) {
			return nil, nil //nolint:nilnil // the misbehaving hook under test
		}, wantStatus: http.StatusInternalServerError},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			environment := newTestEnvironment(t, defaultTestTeams(), func(options *Options) { options.OnLogin = testCase.hook })
			login := environment.startLogin(t, "")

			response := environment.callback(t, login, approve(t, login.Header().Get("Location")))

			require.Equal(t, testCase.wantStatus, response.Code)
			require.Empty(t, response.Result().Cookies(), "no session is started")
			require.Equal(t, "42", environment.outcomes.last(t).Identity.Subject)
		})
	}
}

func TestLogoutEndsTheSessionAndRevokesTheToken(t *testing.T) {
	var loggedOut []*auth.Identity
	environment := newTestEnvironment(t, defaultTestTeams(), func(options *Options) {
		options.PostLogoutURL = "https://www.example.com/goodbye"
		options.OnLogout = func(_ context.Context, identity *auth.Identity) { loggedOut = append(loggedOut, identity) }
	})
	login := environment.login(t)
	token, err := sessionToken(t.Context(), environment.sessionOf(t, login))
	require.NoError(t, err)

	response := environment.serve(withSessionCookie(t, newRequest(t, http.MethodGet, testExternalURL+"/auth/github/logout"), login))

	require.Equal(t, http.StatusFound, response.Code)
	require.Equal(t, "https://www.example.com/goodbye", response.Header().Get("Location"))
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.Equal(t, -1, sessionCookie(t, response).MaxAge)
	_, err = environment.sessionOf(t, login).Identity(t.Context())
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.Equal(t, []string{token.AccessToken}, environment.fake.RevokedTokens())
	require.Len(t, loggedOut, 1)
	require.Equal(t, "42", loggedOut[0].Subject)
	outcome := environment.outcomes.last(t)
	require.Equal(t, auth.Outcome{Provider: "github", Action: auth.ActionLogout, Result: auth.ResultSuccess, Identity: loggedOut[0]}, outcome)
}

func TestLogoutWithFailedRevocationIsADegradedSuccess(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.login(t)
	environment.fake.FailWith(fakeprovider.GitHubEndpointRevoke, http.StatusInternalServerError)

	response := environment.serve(withSessionCookie(t, newRequest(t, http.MethodGet, testExternalURL+"/auth/github/logout"), login))

	require.Equal(t, http.StatusFound, response.Code)
	require.Equal(t, testExternalURL+"/", response.Header().Get("Location"))
	_, err := environment.sessionOf(t, login).Identity(t.Context())
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	outcome := environment.outcomes.last(t)
	require.Equal(t, auth.ResultSuccess, outcome.Result)
	require.ErrorContains(t, outcome.Err, "revoke token")
}

func TestLogoutWithoutSession(t *testing.T) {
	called := false
	environment := newTestEnvironment(t, defaultTestTeams(), func(options *Options) {
		options.OnLogout = func(context.Context, *auth.Identity) { called = true }
	})

	response := environment.serve(newRequest(t, http.MethodGet, testExternalURL+"/auth/github/logout"))

	require.Equal(t, http.StatusFound, response.Code)
	require.False(t, called)
	require.Zero(t, environment.fake.Calls(fakeprovider.GitHubEndpointRevoke))
	require.Equal(t, auth.Outcome{Provider: "github", Action: auth.ActionLogout, Result: auth.ResultSuccess}, environment.outcomes.last(t))
}

func TestLogoutFailsWhenTheSessionCannotBeEnded(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.login(t)
	environment.backend.failRevoke.Store(true)

	response := environment.serve(withSessionCookie(t, newRequest(t, http.MethodGet, testExternalURL+"/auth/github/logout"), login))

	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.Empty(t, environment.fake.RevokedTokens())
	outcome := environment.outcomes.last(t)
	require.Equal(t, auth.ResultError, outcome.Result)
	require.ErrorIs(t, outcome.Err, errBackendDown)
}

func TestLogoutIgnoresAClientDisconnect(t *testing.T) {
	var loggedOut []*auth.Identity
	environment := newTestEnvironment(t, defaultTestTeams(), func(options *Options) {
		options.OnLogout = func(_ context.Context, identity *auth.Identity) { loggedOut = append(loggedOut, identity) }
	})
	login := environment.login(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request := withSessionCookie(t, newRequest(t, http.MethodGet, testExternalURL+"/auth/github/logout"), login).WithContext(ctx)

	response := environment.serve(request)

	require.Equal(t, http.StatusFound, response.Code)
	require.Len(t, environment.fake.RevokedTokens(), 1)
	require.Len(t, loggedOut, 1)
	outcome := environment.outcomes.last(t)
	require.NoError(t, outcome.Err)
	require.Equal(t, "42", outcome.Identity.Subject)
}

func TestLogoutWithAnUnreadableSessionIsADegradedSuccess(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.login(t)
	environment.backend.failGet.Store(true)

	response := environment.serve(withSessionCookie(t, newRequest(t, http.MethodGet, testExternalURL+"/auth/github/logout"), login))

	require.Equal(t, http.StatusFound, response.Code)
	require.Equal(t, -1, sessionCookie(t, response).MaxAge)
	environment.backend.failGet.Store(false)
	_, err := environment.sessionOf(t, login).Identity(t.Context())
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "the session is ended all the same")
	outcome := environment.outcomes.last(t)
	require.Equal(t, auth.ResultSuccess, outcome.Result)
	require.ErrorIs(t, outcome.Err, errBackendDown)
}

func TestRefreshTeams(t *testing.T) {
	editorHook := func(options *Options) {
		options.OnLogin = func(_ context.Context, identity *auth.Identity) (*auth.Identity, error) {
			mapped := identity.Clone()
			mapped.Roles = append(mapped.Roles, "editor")
			return mapped, nil
		}
	}
	developers := fakeprovider.GitHubTeam{Organization: "acme", Slug: "developers"}
	testCases := []struct {
		name       string
		startTeams []fakeprovider.GitHubTeam
		teams      []fakeprovider.GitHubTeam
		wantTeams  []string
		wantRoles  []string
	}{
		{
			name:       "becomes admin",
			startTeams: []fakeprovider.GitHubTeam{developers},
			teams:      []fakeprovider.GitHubTeam{developers, {Organization: "ACME", Slug: "Admins"}},
			wantTeams:  []string{"acme/admins", "acme/developers"},
			wantRoles:  []string{"editor", auth.RoleAdmin},
		},
		{
			name:       "loses admin, keeps other roles",
			startTeams: []fakeprovider.GitHubTeam{developers, {Organization: "acme", Slug: "admins"}},
			teams:      []fakeprovider.GitHubTeam{developers, {Organization: "acme", Slug: "ops"}},
			wantTeams:  []string{"acme/developers", "acme/ops"},
			wantRoles:  []string{"editor"},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			environment := newTestEnvironment(t, testCase.startTeams, editorHook)
			login := environment.login(t)
			environment.fake.SetTeams(testCase.teams)

			response := environment.serve(withSessionCookie(t, newRequest(t, http.MethodPost, testExternalURL+"/auth/github/refresh-teams"), login))

			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			var body auth.IdentityResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, testCase.wantTeams, body.Teams)
			require.Equal(t, testCase.wantRoles, body.Roles)
			stored := environment.identityOf(t, login)
			require.Equal(t, testCase.wantTeams, stored.Teams)
			require.Equal(t, testCase.wantRoles, stored.Roles)
			outcome := environment.outcomes.last(t)
			require.Equal(t, auth.ActionRefreshTeams, outcome.Action)
			require.Equal(t, auth.ResultSuccess, outcome.Result)
		})
	}
}

func TestRefreshTeamsRefusals(t *testing.T) {
	testCases := []struct {
		name        string
		prepare     func(environment *testEnvironment)
		wantStatus  int
		wantEnded   bool
		wantResult  auth.Result
		withoutUser bool
	}{
		{
			name: "removed from the allowed team",
			prepare: func(environment *testEnvironment) {
				environment.fake.SetTeams([]fakeprovider.GitHubTeam{{Organization: "acme", Slug: "ops"}})
			},
			wantStatus: http.StatusForbidden, wantEnded: true, wantResult: auth.ResultDenied,
		},
		{
			name:       "token revoked at GitHub",
			prepare:    failing(fakeprovider.GitHubEndpointTeams, http.StatusUnauthorized),
			wantStatus: http.StatusUnauthorized, wantEnded: true, wantResult: auth.ResultDenied,
		},
		{
			name:       "GitHub down",
			prepare:    failing(fakeprovider.GitHubEndpointTeams, http.StatusBadGateway),
			wantStatus: http.StatusInternalServerError, wantResult: auth.ResultError,
		},
		{
			name:       "session store fails",
			prepare:    func(environment *testEnvironment) { environment.backend.failPut.Store(true) },
			wantStatus: http.StatusInternalServerError, wantResult: auth.ResultError,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			environment := newTestEnvironment(t, defaultTestTeams(), nil)
			login := environment.login(t)
			testCase.prepare(environment)

			response := environment.serve(withSessionCookie(t, newRequest(t, http.MethodPost, testExternalURL+"/auth/github/refresh-teams"), login))

			require.Equal(t, testCase.wantStatus, response.Code, response.Body.String())
			_, err := environment.sessionOf(t, login).Identity(t.Context())
			if testCase.wantEnded {
				require.ErrorIs(t, err, auth.ErrUnauthenticated)
				require.Equal(t, -1, sessionCookie(t, response).MaxAge)
			} else {
				require.NoError(t, err)
			}
			outcome := environment.outcomes.last(t)
			require.Equal(t, auth.ActionRefreshTeams, outcome.Action)
			require.Equal(t, testCase.wantResult, outcome.Result)
			require.Equal(t, "42", outcome.Identity.Subject)
		})
	}
}

func TestRefreshTeamsRefusesSessionsItDoesNotOwn(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)

	response := environment.serve(newRequest(t, http.MethodPost, testExternalURL+"/auth/github/refresh-teams"))
	require.Equal(t, http.StatusUnauthorized, response.Code, "no session")

	passwordSession := startSessionWith(t, environment, &auth.Identity{Provider: "password", Subject: "user-1", Active: true})
	response = environment.serve(withSessionCookie(t, newRequest(t, http.MethodPost, testExternalURL+"/auth/github/refresh-teams"), passwordSession))
	require.Equal(t, http.StatusUnauthorized, response.Code, "another provider's session")
	_, err := environment.sessionOf(t, passwordSession).Identity(t.Context())
	require.NoError(t, err, "another provider's session is not ended")
	require.Zero(t, environment.fake.Calls(fakeprovider.GitHubEndpointTeams))
}

func TestRefreshTeamsKeepsTheImpersonatedIdentity(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.login(t)
	current := environment.sessionOf(t, login)
	admin, err := current.Identity(t.Context())
	require.NoError(t, err)
	require.NoError(t, current.SaveIdentity(t.Context(), &auth.Identity{Provider: "password", Subject: "user-1", Active: true, Impersonator: admin}))
	environment.fake.SetTeams([]fakeprovider.GitHubTeam{{Organization: "acme", Slug: "developers"}})

	response := environment.serve(withSessionCookie(t, newRequest(t, http.MethodPost, testExternalURL+"/auth/github/refresh-teams"), login))

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	stored := environment.identityOf(t, login)
	require.Equal(t, "user-1", stored.Subject)
	require.Equal(t, []string{"acme/developers"}, stored.Impersonator.Teams)
	require.Empty(t, stored.Impersonator.Roles)
}

// startSessionWith starts a session holding identity and returns the response that set its cookie.
func startSessionWith(t *testing.T, environment *testEnvironment, identity *auth.Identity) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	current, err := environment.store.Start(t.Context(), recorder, newRequest(t, http.MethodGet, testExternalURL+"/"))
	require.NoError(t, err)
	require.NoError(t, current.SaveIdentity(t.Context(), identity))
	return recorder
}

func TestRefresh(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.login(t)
	current := environment.sessionOf(t, login)
	identity := environment.identityOf(t, login)
	identity.Roles = append(identity.Roles, "editor")

	t.Run("replaces teams and the admin role", func(t *testing.T) {
		environment.fake.SetTeams([]fakeprovider.GitHubTeam{{Organization: "acme", Slug: "developers"}})
		before := identity.Clone()

		refreshed, err := environment.provider.Refresh(t.Context(), current, identity)

		require.NoError(t, err)
		require.Equal(t, []string{"acme/developers"}, refreshed.Teams)
		require.Equal(t, []string{"editor"}, refreshed.Roles)
		require.Equal(t, before, identity, "the argument is not modified")
	})
	t.Run("no allowed team any more", func(t *testing.T) {
		environment.fake.SetTeams(nil)
		_, err := environment.provider.Refresh(t.Context(), current, identity)
		require.ErrorIs(t, err, auth.ErrForbidden)
	})
	t.Run("token rejected", func(t *testing.T) {
		environment.fake.FailWith(fakeprovider.GitHubEndpointTeams, http.StatusUnauthorized)
		defer environment.fake.FailWith(fakeprovider.GitHubEndpointTeams, 0)
		_, err := environment.provider.Refresh(t.Context(), current, identity)
		require.ErrorIs(t, err, auth.ErrUnauthenticated)
	})
	t.Run("GitHub down is a plain error", func(t *testing.T) {
		environment.fake.FailWith(fakeprovider.GitHubEndpointTeams, http.StatusServiceUnavailable)
		defer environment.fake.FailWith(fakeprovider.GitHubEndpointTeams, 0)
		_, err := environment.provider.Refresh(t.Context(), current, identity)
		require.Error(t, err)
		require.NotErrorIs(t, err, auth.ErrUnauthenticated)
		require.NotErrorIs(t, err, auth.ErrForbidden)
	})
	t.Run("session without token", func(t *testing.T) {
		other := environment.sessionOf(t, startSessionWith(t, environment, &auth.Identity{Provider: "password", Subject: "user-1"}))
		_, err := environment.provider.Refresh(t.Context(), other, identity)
		require.ErrorIs(t, err, auth.ErrUnauthenticated)
	})
	t.Run("nil identity", func(t *testing.T) {
		_, err := environment.provider.Refresh(t.Context(), current, nil)
		require.Error(t, err)
	})
}

func TestHTTPClientSendsTheTokenToGitHubOnly(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	login := environment.login(t)
	var mutex sync.Mutex
	var foreignAuthorization []string
	foreign := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		foreignAuthorization = append(foreignAuthorization, request.Header.Get("Authorization"))
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(foreign.Close)

	client, err := environment.provider.HTTPClient(t.Context(), environment.sessionOf(t, login))
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, statusOf(t, client, environment.fake.APIURL()+"/user"))
	require.Equal(t, http.StatusNoContent, statusOf(t, client, foreign.URL+"/collect"))
	mutex.Lock()
	defer mutex.Unlock()
	require.Equal(t, []string{""}, foreignAuthorization)
}

func TestHTTPClientRefusesSessionsWithoutToken(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), nil)
	passwordSession := startSessionWith(t, environment, &auth.Identity{Provider: "password", Subject: "user-1"})

	client, err := environment.provider.HTTPClient(t.Context(), environment.sessionOf(t, passwordSession))

	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.Nil(t, client)
}

func statusOf(t *testing.T, client *http.Client, target string) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	return response.StatusCode
}

func TestHandlersWorkWithoutObserver(t *testing.T) {
	environment := newTestEnvironment(t, defaultTestTeams(), func(options *Options) { options.Observer = nil })

	response := environment.login(t)

	require.Equal(t, testExternalURL+"/", response.Header().Get("Location"))
	require.Empty(t, environment.outcomes.outcomes)
}
