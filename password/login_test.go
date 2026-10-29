package password

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

func TestLogin(t *testing.T) {
	testCases := []struct {
		name       string
		options    Options
		identifier string
		password   string
		wantStatus int
		wantCode   string
		wantReason string
	}{
		{name: "by username", identifier: "ada", password: testPassword, wantStatus: http.StatusOK},
		{name: "by email", identifier: "ada@example.com", password: testPassword, wantStatus: http.StatusOK},
		{name: "by email in another case", identifier: "ADA@example.com", password: testPassword, wantStatus: http.StatusOK},
		{name: "wrong password", identifier: "ada", password: "wrong password", wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials", wantReason: "wrong password"},
		{name: "empty password", identifier: "ada", password: "", wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials", wantReason: "wrong password"},
		{name: "unknown user", identifier: "grace", password: testPassword, wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials", wantReason: "unknown user"},
		{name: "unknown email", identifier: "grace@example.com", password: testPassword, wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials", wantReason: "unknown user"},
		{
			name: "username while username login is disabled", options: Options{DisableUsernameLogin: true}, identifier: "ada", password: testPassword,
			wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials", wantReason: "unknown user",
		},
		{
			name: "email while email login is disabled", options: Options{DisableEmailLogin: true}, identifier: "ada@example.com", password: testPassword,
			wantStatus: http.StatusUnauthorized, wantCode: "invalid_credentials", wantReason: "unknown user",
		},
		{name: "email while username login is disabled", options: Options{DisableUsernameLogin: true}, identifier: "ada@example.com", password: testPassword, wantStatus: http.StatusOK},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFixture(t, testCase.options)
			user := fixture.createUser(t, "ada", "ada@example.com")
			browser := fixture.newClient(t)

			recorder := browser.post("/auth/password/login", map[string]any{"identifier": testCase.identifier, "password": testCase.password})

			outcome := fixture.outcomes.last(t)
			require.Equal(t, auth.ActionLogin, outcome.Action)
			require.Equal(t, "password", outcome.Provider)
			if testCase.wantStatus != http.StatusOK {
				requireRefusal(t, recorder, testCase.wantStatus, testCase.wantCode)
				require.False(t, browser.hasSession())
				require.Equal(t, auth.ResultDenied, outcome.Result)
				var refusal *auth.Error
				require.True(t, errors.As(outcome.Err, &refusal))
				require.Equal(t, testCase.wantReason, refusal.Reason)
				return
			}
			response := requireIdentity(t, recorder, http.StatusOK, user)
			require.Equal(t, "ada", response.Username)
			require.Equal(t, "ada@example.com", response.Email)
			require.True(t, response.Active)
			require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			require.Equal(t, auth.ResultSuccess, outcome.Result)
			require.NoError(t, outcome.Err)
			require.Equal(t, user.ID, outcome.Identity.UserID)
			identity, err := fixture.sessionIdentity(t, browser)
			require.NoError(t, err)
			require.Equal(t, &auth.Identity{Provider: "password", Subject: user.ID.String(), UserID: user.ID, Username: "ada", Email: "ada@example.com", Active: true}, identity)
		})
	}
}

func TestLoginRefusesMalformedRequests(t *testing.T) {
	testCases := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "no content type", body: `{"identifier":"ada","password":"x"}`},
		{name: "form content type", contentType: "application/x-www-form-urlencoded", body: "identifier=ada&password=x"},
		{name: "unknown field", contentType: "application/json", body: `{"identifier":"ada","password":"x","remember":true}`},
		{name: "trailing data", contentType: "application/json", body: `{"identifier":"ada","password":"x"} {}`},
		{name: "not JSON", contentType: "application/json", body: `identifier=ada`},
		{name: "above 64 KiB", contentType: "application/json", body: `{"identifier":"ada","password":"` + strings.Repeat("a", 64<<10) + `"}`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFixture(t, Options{})
			fixture.createUser(t, "ada", "")
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/password/login", bytes.NewBufferString(testCase.body))
			if testCase.contentType != "" {
				request.Header.Set("Content-Type", testCase.contentType)
			}

			recorder := fixture.newClient(t).send(request)

			requireRefusal(t, recorder, http.StatusBadRequest, "invalid_request")
			require.Equal(t, auth.ResultDenied, fixture.outcomes.last(t).Result)
		})
	}
}

func TestLoginRotatesTheSession(t *testing.T) {
	fixture := newFixture(t, Options{})
	fixture.createUser(t, "ada", "")
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusOK, browser.login("ada").Code)
	before := browser.copy()

	require.Equal(t, http.StatusOK, browser.login("ada").Code)

	require.NotEqual(t, before.cookies["auth_session"].Value, browser.cookies["auth_session"].Value)
	_, err := fixture.sessionIdentity(t, before)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	_, err = fixture.sessionIdentity(t, browser)
	require.NoError(t, err)
}

func TestLoginStorageFailure(t *testing.T) {
	fixture := newFixture(t, Options{})
	fixture.createUser(t, "ada", "")
	fixture.failStorage("GetUserByUsername")

	recorder := fixture.newClient(t).login("ada")

	requireRefusal(t, recorder, http.StatusInternalServerError, "internal")
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.ResultError, outcome.Result)
	require.ErrorIs(t, outcome.Err, errStorageDown)
}

func TestOnLogin(t *testing.T) {
	testCases := []struct {
		name       string
		hook       auth.Hook
		wantStatus int
		wantResult auth.Result
		wantRoles  []string
	}{
		{
			name: "maps the identity",
			hook: func(_ context.Context, identity *auth.Identity) (*auth.Identity, error) {
				mapped := identity.Clone()
				mapped.Roles = []string{auth.RoleAdmin}
				return mapped, nil
			},
			wantStatus: http.StatusOK, wantResult: auth.ResultSuccess, wantRoles: []string{auth.RoleAdmin},
		},
		{
			name: "refuses",
			hook: func(context.Context, *auth.Identity) (*auth.Identity, error) {
				return nil, &auth.Error{Kind: auth.ErrForbidden, Reason: "inactive user"}
			},
			wantStatus: http.StatusForbidden, wantResult: auth.ResultDenied,
		},
		{
			name:       "fails",
			hook:       func(context.Context, *auth.Identity) (*auth.Identity, error) { return nil, errStorageDown },
			wantStatus: http.StatusInternalServerError, wantResult: auth.ResultError,
		},
		{
			name:       "returns no identity",
			hook:       func(context.Context, *auth.Identity) (*auth.Identity, error) { return nil, nil },
			wantStatus: http.StatusInternalServerError, wantResult: auth.ResultError,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFixture(t, Options{OnLogin: testCase.hook})
			fixture.createUser(t, "ada", "")
			browser := fixture.newClient(t)

			recorder := browser.login("ada")

			require.Equal(t, testCase.wantStatus, recorder.Code)
			require.Equal(t, testCase.wantResult, fixture.outcomes.last(t).Result)
			if testCase.wantStatus != http.StatusOK {
				require.False(t, browser.hasSession())
				return
			}
			require.Equal(t, testCase.wantRoles, decodeBody[auth.IdentityResponse](t, recorder).Roles)
			identity, err := fixture.sessionIdentity(t, browser)
			require.NoError(t, err)
			require.Equal(t, testCase.wantRoles, identity.Roles)
		})
	}
}

func TestLogout(t *testing.T) {
	var loggedOut []*auth.Identity
	fixture := newFixture(t, Options{OnLogout: func(_ context.Context, identity *auth.Identity) { loggedOut = append(loggedOut, identity) }})
	user := fixture.createUser(t, "ada", "")
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusOK, browser.login("ada").Code)
	stolen := browser.copy()
	fixture.outcomes.take()

	recorder := browser.post("/auth/password/logout", nil)

	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.Empty(t, recorder.Body.String())
	require.False(t, browser.hasSession())
	_, err := fixture.sessionIdentity(t, stolen)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.Len(t, loggedOut, 1)
	require.Equal(t, user.ID, loggedOut[0].UserID)
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.Outcome{Provider: "password", Action: auth.ActionLogout, Result: auth.ResultSuccess, Identity: loggedOut[0]}, outcome)

	recorder = fixture.newClient(t).send(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/password/logout", http.NoBody))

	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Len(t, loggedOut, 1)
	require.Nil(t, fixture.outcomes.last(t).Identity)
}

func TestLogoutWithADisconnectedClient(t *testing.T) {
	var loggedOut []*auth.Identity
	var hookContextError error
	fixture := newFixture(t, Options{OnLogout: func(ctx context.Context, identity *auth.Identity) {
		loggedOut = append(loggedOut, identity)
		hookContextError = ctx.Err()
	}})
	user := fixture.createUser(t, "ada", "")
	browser := loggedInClient(t, fixture)
	fixture.outcomes.take()
	fixture.useBackend(t, cancellableBackend{Backend: fixture.backend})
	disconnected, cancel := context.WithCancel(t.Context())
	cancel()

	recorder := browser.send(httptest.NewRequestWithContext(disconnected, http.MethodPost, "/auth/password/logout", http.NoBody))

	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Len(t, loggedOut, 1)
	require.Equal(t, user.ID, loggedOut[0].UserID)
	require.NoError(t, hookContextError, "OnLogout gets a context the disconnect does not cancel")
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.ResultSuccess, outcome.Result)
	require.NoError(t, outcome.Err)
	require.Equal(t, loggedOut[0], outcome.Identity)
}

func TestLogoutReportsAFailedSessionRead(t *testing.T) {
	var loggedOut []*auth.Identity
	fixture := newFixture(t, Options{OnLogout: func(_ context.Context, identity *auth.Identity) { loggedOut = append(loggedOut, identity) }})
	fixture.createUser(t, "ada", "")
	browser := loggedInClient(t, fixture)
	stolen := browser.copy()
	fixture.outcomes.take()
	fixture.failSessions(t, "Get")

	recorder := browser.post("/auth/password/logout", nil)

	require.Equal(t, http.StatusNoContent, recorder.Code)
	_, err := fixture.sessionIdentity(t, stolen)
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "the session ends all the same")
	require.Empty(t, loggedOut)
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.ResultSuccess, outcome.Result)
	require.ErrorIs(t, outcome.Err, errStorageDown, "the outcome tells that OnLogout missed the identity")
	require.Nil(t, outcome.Identity)
}

func TestLogoutRefusesACrossSiteRequest(t *testing.T) {
	var loggedOut []*auth.Identity
	fixture := newFixture(t, Options{OnLogout: func(_ context.Context, identity *auth.Identity) { loggedOut = append(loggedOut, identity) }})
	fixture.createUser(t, "ada", "")
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusOK, browser.login("ada").Code)
	fixture.outcomes.take()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/password/logout", http.NoBody)
	request.Header.Set("Sec-Fetch-Site", "cross-site")

	recorder := browser.send(request)

	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Equal(t, "forbidden", decodeBody[auth.ErrorResponse](t, recorder).Code)
	require.Empty(t, recorder.Header().Values("Set-Cookie"))
	_, err := fixture.sessionIdentity(t, browser)
	require.NoError(t, err, "the session is untouched")
	require.Empty(t, loggedOut)
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.ActionLogout, outcome.Action)
	require.Equal(t, auth.ResultDenied, outcome.Result)
	require.ErrorIs(t, outcome.Err, auth.ErrForbidden)
}

func TestRegistration(t *testing.T) {
	testCases := []struct {
		name       string
		options    Options
		body       map[string]any
		wantStatus int
		wantCode   string
	}{
		{name: "username and email", body: map[string]any{"username": "grace", "email": "grace@example.com", "password": testPassword}, wantStatus: http.StatusCreated},
		{name: "email only", body: map[string]any{"email": "grace@example.com", "password": testPassword}, wantStatus: http.StatusCreated},
		{name: "taken username", body: map[string]any{"username": "Ada", "password": testPassword}, wantStatus: http.StatusConflict, wantCode: "user_exists"},
		{name: "taken email", body: map[string]any{"username": "grace", "email": "ada@example.com", "password": testPassword}, wantStatus: http.StatusConflict, wantCode: "user_exists"},
		{name: "neither username nor email", body: map[string]any{"password": testPassword}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "disabled kind", options: Options{DisableEmailLogin: true}, body: map[string]any{"email": "grace@example.com", "password": testPassword}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "invalid username", body: map[string]any{"username": "g", "password": testPassword}, wantStatus: http.StatusBadRequest, wantCode: "invalid_username"},
		{name: "invalid email", body: map[string]any{"email": "grace@", "password": testPassword}, wantStatus: http.StatusBadRequest, wantCode: "invalid_email"},
		{name: "weak password", body: map[string]any{"username": "grace", "password": "short"}, wantStatus: http.StatusBadRequest, wantCode: "weak_password"},
		{name: "unknown field", body: map[string]any{"username": "grace", "password": testPassword, "admin": true}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.options.EnableRegistration = true
			fixture := newFixture(t, testCase.options)
			fixture.createUser(t, "ada", "ada@example.com")
			browser := fixture.newClient(t)

			recorder := browser.post("/auth/password/register", testCase.body)

			outcome := fixture.outcomes.last(t)
			require.Equal(t, auth.ActionRegister, outcome.Action)
			if testCase.wantStatus != http.StatusCreated {
				requireRefusal(t, recorder, testCase.wantStatus, testCase.wantCode)
				require.False(t, browser.hasSession())
				return
			}
			require.Equal(t, http.StatusCreated, recorder.Code, recorder.Body.String())
			require.Equal(t, auth.ResultSuccess, outcome.Result)
			created := fixture.storedUser(t, outcome.Identity.UserID)
			requireIdentity(t, recorder, http.StatusCreated, created)
			matched, err := Verify(testPassword, created.PasswordHash)
			require.NoError(t, err)
			require.True(t, matched)
			identity, err := fixture.sessionIdentity(t, browser)
			require.NoError(t, err)
			require.Equal(t, created.ID, identity.UserID)
		})
	}
}

func TestRegistrationWithRequiredTOTPEnrollsFirst(t *testing.T) {
	options := totpOptions()
	options.TOTP.Required = true
	options.EnableRegistration = true
	fixture := newFixture(t, options)
	browser := fixture.newClient(t)

	recorder := browser.post("/auth/password/register", map[string]any{"username": "grace", "password": testPassword})

	require.Equal(t, http.StatusAccepted, recorder.Code)
	require.Equal(t, ChallengeTOTPSetup, decodeBody[challengeResponse](t, recorder).Challenge)
	require.Equal(t, auth.ResultChallenge, fixture.outcomes.last(t).Result)
	_, err := fixture.sessionIdentity(t, browser)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
}

func TestRegistrationStorageFailure(t *testing.T) {
	fixture := newFixture(t, Options{EnableRegistration: true})
	fixture.failStorage("CreateUser")

	recorder := fixture.newClient(t).post("/auth/password/register", map[string]any{"username": "grace", "password": testPassword})

	requireRefusal(t, recorder, http.StatusInternalServerError, "internal")
	require.ErrorIs(t, fixture.outcomes.last(t).Err, errStorageDown)
}

func TestRefresh(t *testing.T) {
	fixture := newFixture(t, Options{})
	user := fixture.createUser(t, "ada", "ada@example.com")
	current := identityOf(user)
	current.Roles = []string{auth.RoleAdmin}
	current.Data = map[string]any{"tenant": "a"}
	require.NoError(t, fixture.storage.update(user.ID, func(stored *memoryUser) error {
		stored.user.Username = new("ada_lovelace")
		stored.user.Email = nil
		return nil
	}))

	refreshed, err := fixture.provider.Refresh(t.Context(), session.Session{}, current)

	require.NoError(t, err)
	want := current.Clone()
	want.Username = "ada_lovelace"
	want.Email = ""
	require.Equal(t, want, refreshed)
	require.Equal(t, "ada", current.Username)
}

func TestRefreshRefuses(t *testing.T) {
	fixture := newFixture(t, Options{})
	user := fixture.createUser(t, "ada", "")

	refreshed, err := fixture.provider.Refresh(t.Context(), session.Session{}, identityOf(&User{ID: uuid.New()}))
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.Nil(t, refreshed)

	fixture.failStorage("GetUserByID")
	refreshed, err = fixture.provider.Refresh(t.Context(), session.Session{}, identityOf(user))
	require.ErrorIs(t, err, errStorageDown)
	require.NotErrorIs(t, err, auth.ErrUnauthenticated)
	require.Nil(t, refreshed)
}
