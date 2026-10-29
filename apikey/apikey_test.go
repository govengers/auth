package apikey_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
)

const (
	buildSecret = "build-secret-0123456789"
	adminSecret = "admin-secret-0123456789"
)

var buildPermissions = []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}, {Resource: auth.AllResources, Access: auth.AccessRead}}

type contextKey struct{}

// seen is what the protected handler observed.
type seen struct {
	called   bool
	identity *auth.Identity
}

// headerValues are request header names with their values.
type headerValues map[string]string

// requestWith builds a GET request carrying the given headers.
func requestWith(t *testing.T, requestHeaders headerValues) *http.Request {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/builds", nil)
	for name, value := range requestHeaders {
		request.Header.Set(name, value)
	}
	return request
}

// serve runs request through the middleware in front of a handler that records what it sees.
func serve(authenticator *apikey.Authenticator, request *http.Request) (*httptest.ResponseRecorder, seen) {
	var observed seen
	handler := authenticator.Middleware()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observed = seen{called: true, identity: auth.IdentityFrom(request.Context())}
		writer.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder, observed
}

func newStatic(t *testing.T, options apikey.Options) *apikey.Authenticator {
	t.Helper()
	options.Keys = []apikey.Key{
		{Name: "build", Secret: buildSecret, Permissions: slices.Clone(buildPermissions)},
		{Name: "admin", Secret: adminSecret, Roles: []string{auth.RoleAdmin}},
	}
	authenticator, err := apikey.New(&options)
	require.NoError(t, err)
	return authenticator
}

func newResolving(t *testing.T, resolver apikey.Resolver) *apikey.Authenticator {
	t.Helper()
	authenticator, err := apikey.New(&apikey.Options{Resolver: resolver})
	require.NoError(t, err)
	return authenticator
}

func requireRefused(t *testing.T, recorder *httptest.ResponseRecorder, observed seen, status int, body string) {
	t.Helper()
	require.Equal(t, status, recorder.Code)
	require.JSONEq(t, body, recorder.Body.String())
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.False(t, observed.called, "a refused request must not reach the handler")
}

const (
	invalidKeyBody = `{"code":"invalid_api_key","message":"authentication required"}`
	internalBody   = `{"code":"internal","message":"internal error"}`
)

func TestNew(t *testing.T) {
	resolver := func(context.Context, string) (*auth.Identity, error) { return nil, nil }
	build := apikey.Key{Name: "build", Secret: buildSecret}
	testCases := []struct {
		name      string
		options   *apikey.Options
		wantError string
	}{
		{name: "nil options", options: nil, wantError: "options are required"},
		{name: "neither keys nor resolver", options: &apikey.Options{}, wantError: "at least one of Keys and Resolver"},
		{name: "keys only", options: &apikey.Options{Keys: []apikey.Key{build}}},
		{name: "resolver only", options: &apikey.Options{Resolver: resolver}},
		{name: "keys and resolver", options: &apikey.Options{Keys: []apikey.Key{build}, Resolver: resolver}},
		{name: "custom header", options: &apikey.Options{Keys: []apikey.Key{build}, HeaderName: "X-Token"}},
		{name: "authorization header", options: &apikey.Options{Keys: []apikey.Key{build}, HeaderName: "authorization"}, wantError: "HeaderName must not be Authorization"},
		{name: "empty name", options: &apikey.Options{Keys: []apikey.Key{{Secret: buildSecret}}}, wantError: "key 1: key name is required"},
		{name: "blank name", options: &apikey.Options{Keys: []apikey.Key{{Name: "  ", Secret: buildSecret}}}, wantError: "key 1: key name is required"},
		{name: "secret one byte short", options: &apikey.Options{Keys: []apikey.Key{{Name: "build", Secret: "0123456789abcde"}}}, wantError: "shorter than 16 bytes"},
		{name: "secret of minimum size", options: &apikey.Options{Keys: []apikey.Key{{Name: "build", Secret: "0123456789abcdef"}}}},
		{name: "secret with trailing space", options: &apikey.Options{Keys: []apikey.Key{{Name: "build", Secret: buildSecret + " "}}}, wantError: "leading or trailing whitespace"},
		{name: "duplicate name", options: &apikey.Options{Keys: []apikey.Key{build, {Name: "build", Secret: adminSecret}}}, wantError: "key 2: name or secret is used by another key"},
		{name: "duplicate secret", options: &apikey.Options{Keys: []apikey.Key{build, {Name: "other", Secret: buildSecret}}}, wantError: "key 2: name or secret is used by another key"},
		{name: "valid permissions", options: &apikey.Options{Keys: []apikey.Key{{Name: "build", Secret: buildSecret, Permissions: buildPermissions}}}},
		{name: "invalid permission access", options: &apikey.Options{Keys: []apikey.Key{{Name: "build", Secret: buildSecret, Permissions: []auth.Permission{{Resource: "builds", Access: "admin"}}}}}, wantError: "key 1: permission"},
		{name: "invalid permission resource", options: &apikey.Options{Keys: []apikey.Key{{Name: "build", Secret: buildSecret, Permissions: []auth.Permission{{Access: auth.AccessRead}}}}}, wantError: "key 1: permission"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator, err := apikey.New(testCase.options)

			if testCase.wantError != "" {
				require.ErrorContains(t, err, testCase.wantError)
				require.Nil(t, authenticator)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, authenticator)
		})
	}
}

func TestNewErrorNeverContainsSecret(t *testing.T) {
	_, err := apikey.New(&apikey.Options{Keys: []apikey.Key{
		{Name: "build", Secret: buildSecret},
		{Name: "build", Secret: adminSecret},
	}})

	require.Error(t, err)
	require.NotContains(t, err.Error(), buildSecret)
	require.NotContains(t, err.Error(), adminSecret)
}

func TestNewLeavesOptionsAlone(t *testing.T) {
	options := &apikey.Options{Keys: []apikey.Key{{Name: "admin", Secret: adminSecret, Roles: []string{auth.RoleAdmin}, Permissions: slices.Clone(buildPermissions)}}}

	authenticator, err := apikey.New(options)
	require.NoError(t, err)
	options.Keys[0].Roles[0] = "tampered"
	options.Keys[0].Permissions[0] = auth.Permission{Resource: "tampered", Access: auth.AccessWrite}
	options.Keys[0].Name = "tampered"

	require.Empty(t, options.HeaderName, "the default must not be written back")
	_, observed := serve(authenticator, requestWith(t, headerValues{"X-API-Key": adminSecret}))
	require.Equal(t, "admin", observed.identity.Subject)
	require.Equal(t, []string{auth.RoleAdmin}, observed.identity.Roles)
	require.Equal(t, buildPermissions, observed.identity.Permissions)
}

func TestMiddlewareAuthenticatesStaticKeys(t *testing.T) {
	testCases := []struct {
		name            string
		headers         headerValues
		wantSubject     string
		wantRoles       []string
		wantPermissions []auth.Permission
	}{
		{name: "X-API-Key", headers: headerValues{"X-API-Key": buildSecret}, wantSubject: "build", wantPermissions: buildPermissions},
		{name: "bearer", headers: headerValues{"Authorization": "Bearer " + adminSecret}, wantSubject: "admin", wantRoles: []string{auth.RoleAdmin}},
		{name: "whitespace around the header value", headers: headerValues{"X-API-Key": "  " + buildSecret + "\t"}, wantSubject: "build", wantPermissions: buildPermissions},
		{name: "extra whitespace after bearer", headers: headerValues{"Authorization": "Bearer   " + buildSecret + " "}, wantSubject: "build", wantPermissions: buildPermissions},
		{name: "header wins over bearer", headers: headerValues{"X-API-Key": buildSecret, "Authorization": "Bearer " + adminSecret}, wantSubject: "build", wantPermissions: buildPermissions},
		{name: "blank header falls back to bearer", headers: headerValues{"X-API-Key": "  ", "Authorization": "Bearer " + adminSecret}, wantSubject: "admin", wantRoles: []string{auth.RoleAdmin}},
		{name: "lower case scheme", headers: headerValues{"Authorization": "bearer " + buildSecret}, wantSubject: "build", wantPermissions: buildPermissions},
		{name: "upper case scheme", headers: headerValues{"Authorization": "BEARER " + adminSecret}, wantSubject: "admin", wantRoles: []string{auth.RoleAdmin}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder, observed := serve(newStatic(t, apikey.Options{}), requestWith(t, testCase.headers))

			require.Equal(t, http.StatusNoContent, recorder.Code)
			require.True(t, observed.called)
			require.Equal(t, &auth.Identity{
				Provider:    "apikey",
				Subject:     testCase.wantSubject,
				Username:    testCase.wantSubject,
				Active:      true,
				Roles:       testCase.wantRoles,
				Permissions: testCase.wantPermissions,
			}, observed.identity)
		})
	}
}

func TestMiddlewareCustomHeader(t *testing.T) {
	authenticator := newStatic(t, apikey.Options{HeaderName: "X-Service-Token"})

	t.Run("custom header", func(t *testing.T) {
		_, observed := serve(authenticator, requestWith(t, headerValues{"X-Service-Token": buildSecret}))
		require.Equal(t, "build", observed.identity.Subject)
	})
	t.Run("bearer is still accepted", func(t *testing.T) {
		_, observed := serve(authenticator, requestWith(t, headerValues{"Authorization": "Bearer " + buildSecret}))
		require.Equal(t, "build", observed.identity.Subject)
	})
	t.Run("default header is ignored", func(t *testing.T) {
		recorder, observed := serve(authenticator, requestWith(t, headerValues{"X-API-Key": buildSecret}))
		require.Equal(t, http.StatusNoContent, recorder.Code)
		require.True(t, observed.called)
		require.Nil(t, observed.identity)
	})
}

func TestMiddlewareRefusesInvalidKeys(t *testing.T) {
	testCases := []struct {
		name    string
		headers headerValues
	}{
		{name: "unknown key", headers: headerValues{"X-API-Key": "wrong-key-0123456789"}},
		{name: "unknown bearer", headers: headerValues{"Authorization": "Bearer wrong-key-0123456789"}},
		{name: "unknown bearer with a lower case scheme", headers: headerValues{"Authorization": "bearer wrong-key-0123456789"}},
		{name: "prefix of a key", headers: headerValues{"X-API-Key": buildSecret[:16]}},
		{name: "key with extra suffix", headers: headerValues{"X-API-Key": buildSecret + "x"}},
		{name: "key differing in case", headers: headerValues{"X-API-Key": "BUILD-secret-0123456789"}},
		{name: "wrong header is not rescued by a valid bearer", headers: headerValues{"X-API-Key": "wrong", "Authorization": "Bearer " + adminSecret}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder, observed := serve(newStatic(t, apikey.Options{}), requestWith(t, testCase.headers))

			requireRefused(t, recorder, observed, http.StatusUnauthorized, invalidKeyBody)
			require.NotContains(t, recorder.Body.String(), "wrong")
		})
	}
}

func TestMiddlewarePassesRequestsWithoutKey(t *testing.T) {
	testCases := []struct {
		name    string
		headers headerValues
	}{
		{name: "no headers"},
		{name: "blank header", headers: headerValues{"X-API-Key": "   "}},
		{name: "empty bearer", headers: headerValues{"Authorization": "Bearer "}},
		{name: "blank bearer", headers: headerValues{"Authorization": "Bearer    "}},
		{name: "bearer without space", headers: headerValues{"Authorization": "Bearer" + buildSecret}},
		{name: "other scheme", headers: headerValues{"Authorization": "Basic dXNlcjpwYXNz"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			resolved := false
			authenticator := newStatic(t, apikey.Options{Resolver: func(context.Context, string) (*auth.Identity, error) {
				resolved = true
				return nil, nil
			}})

			recorder, observed := serve(authenticator, requestWith(t, testCase.headers))

			require.Equal(t, http.StatusNoContent, recorder.Code)
			require.True(t, observed.called)
			require.Nil(t, observed.identity)
			require.False(t, resolved)
		})
	}
}

func TestMiddlewareGivesEveryRequestItsOwnPermissions(t *testing.T) {
	authenticator := newStatic(t, apikey.Options{})
	handler := authenticator.Middleware()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := auth.IdentityFrom(request.Context())
		_, _ = fmt.Fprint(writer, identity.Permissions)
		identity.Permissions[0] = auth.Permission{Resource: "tampered", Access: auth.AccessWrite}
	}))

	for range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestWith(t, headerValues{"X-API-Key": buildSecret}))
		require.Equal(t, "[builds:write *:read]", recorder.Body.String())
	}
}

func TestMiddlewareGivesEveryRequestItsOwnRoles(t *testing.T) {
	authenticator := newStatic(t, apikey.Options{})
	handler := authenticator.Middleware()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := auth.IdentityFrom(request.Context())
		_, _ = fmt.Fprint(writer, identity.Roles)
		identity.Roles[0] = "tampered"
	}))

	for range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestWith(t, headerValues{"X-API-Key": adminSecret}))
		require.Equal(t, "[admin]", recorder.Body.String())
	}
}

func TestResolver(t *testing.T) {
	testCases := []struct {
		name         string
		resolve      apikey.Resolver
		wantStatus   int
		wantBody     string
		wantIdentity *auth.Identity
	}{
		{
			name: "identity without provider gets apikey",
			resolve: func(context.Context, string) (*auth.Identity, error) {
				return &auth.Identity{Subject: "ci", Active: true}, nil
			},
			wantStatus:   http.StatusNoContent,
			wantIdentity: &auth.Identity{Provider: "apikey", Subject: "ci", Active: true},
		},
		{
			name: "identity keeps its own provider",
			resolve: func(context.Context, string) (*auth.Identity, error) {
				return &auth.Identity{Provider: "billing", Subject: "ci", Active: true}, nil
			},
			wantStatus:   http.StatusNoContent,
			wantIdentity: &auth.Identity{Provider: "billing", Subject: "ci", Active: true},
		},
		{
			name: "unknown key",
			resolve: func(context.Context, string) (*auth.Identity, error) {
				return nil, fmt.Errorf("look up key: %w", auth.ErrUnauthenticated)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   invalidKeyBody,
		},
		{
			name: "unknown key as refusal",
			resolve: func(context.Context, string) (*auth.Identity, error) {
				return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Code: "key_revoked"}
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   invalidKeyBody,
		},
		{
			name:       "no identity and no error",
			resolve:    func(context.Context, string) (*auth.Identity, error) { return nil, nil },
			wantStatus: http.StatusUnauthorized,
			wantBody:   invalidKeyBody,
		},
		{
			name: "failure",
			resolve: func(context.Context, string) (*auth.Identity, error) {
				return nil, errors.New("database password=hunter2 refused")
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   internalBody,
		},
		{
			name: "failure of a refusing kind is still a failure",
			resolve: func(context.Context, string) (*auth.Identity, error) {
				return nil, &auth.Error{Kind: auth.ErrForbidden, Reason: "tenant suspended"}
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   internalBody,
		},
		{
			name: "failure wins over an identity",
			resolve: func(context.Context, string) (*auth.Identity, error) {
				return &auth.Identity{Subject: "ci"}, errors.New("half done")
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   internalBody,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder, observed := serve(newResolving(t, testCase.resolve), requestWith(t, headerValues{"X-API-Key": "issued-key-0123456789"}))

			if testCase.wantIdentity != nil {
				require.Equal(t, http.StatusNoContent, recorder.Code)
				require.Equal(t, testCase.wantIdentity, observed.identity)
				return
			}
			requireRefused(t, recorder, observed, testCase.wantStatus, testCase.wantBody)
			require.NotContains(t, recorder.Body.String(), "hunter2")
		})
	}
}

func TestResolverFailureKeepsAContextErrorDetectable(t *testing.T) {
	var outcomes []auth.Outcome
	authenticator, err := apikey.New(&apikey.Options{
		Resolver: func(ctx context.Context, _ string) (*auth.Identity, error) {
			return nil, fmt.Errorf("query keys: %w", ctx.Err())
		},
		Observer: func(_ context.Context, outcome auth.Outcome) { outcomes = append(outcomes, outcome) },
	})
	require.NoError(t, err)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	request := httptest.NewRequestWithContext(cancelled, http.MethodGet, "/", nil)
	request.Header.Set("X-API-Key", "issued-key-0123456789")

	recorder, _ := serve(authenticator, request)

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Len(t, outcomes, 1)
	require.ErrorIs(t, outcomes[0].Err, context.Canceled, "a client that went away stays distinguishable from a failing resolver")
	require.Equal(t, auth.ResultError, outcomes[0].Result)
}

func TestResolverReceivesTrimmedKeyAndRequestContext(t *testing.T) {
	var gotKey string
	var gotValue any
	authenticator := newResolving(t, func(ctx context.Context, key string) (*auth.Identity, error) {
		gotKey, gotValue = key, ctx.Value(contextKey{})
		return &auth.Identity{Subject: "ci"}, nil
	})
	request := httptest.NewRequestWithContext(context.WithValue(t.Context(), contextKey{}, "request-scoped"), http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer  issued-key ")

	recorder, _ := serve(authenticator, request)

	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, "issued-key", gotKey)
	require.Equal(t, "request-scoped", gotValue)
}

func TestResolverIdentityIsCopied(t *testing.T) {
	readAll := []auth.Permission{{Resource: auth.AllResources, Access: auth.AccessRead}}
	shared := &auth.Identity{Subject: "ci", Roles: []string{"reader"}, Permissions: slices.Clone(readAll)}
	authenticator := newResolving(t, func(context.Context, string) (*auth.Identity, error) { return shared, nil })

	_, observed := serve(authenticator, requestWith(t, headerValues{"X-API-Key": "issued-key-0123456789"}))
	require.Equal(t, readAll, observed.identity.Permissions)
	observed.identity.Roles[0] = "tampered"
	observed.identity.Permissions[0] = auth.Permission{Resource: "tampered", Access: auth.AccessWrite}

	require.NotSame(t, shared, observed.identity)
	require.Empty(t, shared.Provider)
	require.Equal(t, []string{"reader"}, shared.Roles)
	require.Equal(t, readAll, shared.Permissions)
}

func TestResolverIsOnlyAskedAboutUnknownKeys(t *testing.T) {
	var asked []string
	authenticator := newStatic(t, apikey.Options{Resolver: func(_ context.Context, key string) (*auth.Identity, error) {
		asked = append(asked, key)
		return &auth.Identity{Provider: "billing", Subject: "issued"}, nil
	}})

	_, staticSeen := serve(authenticator, requestWith(t, headerValues{"X-API-Key": buildSecret}))
	_, issuedSeen := serve(authenticator, requestWith(t, headerValues{"X-API-Key": "issued-key-0123456789"}))

	require.Equal(t, "build", staticSeen.identity.Subject)
	require.Equal(t, "issued", issuedSeen.identity.Subject)
	require.Equal(t, []string{"issued-key-0123456789"}, asked)
}

func TestObserver(t *testing.T) {
	resolver := func(_ context.Context, key string) (*auth.Identity, error) {
		switch key {
		case "issued-key-0123456789":
			return &auth.Identity{Subject: "issued"}, nil
		case "revoked-key-0123456789":
			return nil, auth.ErrUnauthenticated
		}
		return nil, errors.New("database down")
	}
	testCases := []struct {
		name         string
		options      apikey.Options
		headers      headerValues
		wantResult   auth.Result
		wantSubject  string
		wantCode     int
		wantNoReport bool
	}{
		{name: "static key", headers: headerValues{"X-API-Key": buildSecret}, wantResult: auth.ResultSuccess, wantSubject: "build"},
		{name: "resolved key", options: apikey.Options{Resolver: resolver}, headers: headerValues{"X-API-Key": "issued-key-0123456789"}, wantResult: auth.ResultSuccess, wantSubject: "issued"},
		{name: "unknown static key", headers: headerValues{"X-API-Key": "wrong-key-0123456789"}, wantResult: auth.ResultDenied, wantCode: http.StatusUnauthorized},
		{name: "revoked resolved key", options: apikey.Options{Resolver: resolver}, headers: headerValues{"X-API-Key": "revoked-key-0123456789"}, wantResult: auth.ResultDenied, wantCode: http.StatusUnauthorized},
		{name: "resolver failure", options: apikey.Options{Resolver: resolver}, headers: headerValues{"X-API-Key": "broken-key-0123456789"}, wantResult: auth.ResultError, wantCode: http.StatusInternalServerError},
		{name: "no key", wantNoReport: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var outcomes []auth.Outcome
			options := testCase.options
			options.Observer = func(_ context.Context, outcome auth.Outcome) { outcomes = append(outcomes, outcome) }

			recorder, _ := serve(newStatic(t, options), requestWith(t, testCase.headers))

			if testCase.wantNoReport {
				require.Empty(t, outcomes)
				return
			}
			require.Len(t, outcomes, 1)
			outcome := outcomes[0]
			require.Equal(t, "apikey", outcome.Provider)
			require.Equal(t, auth.ActionAuthenticate, outcome.Action)
			require.Equal(t, testCase.wantResult, outcome.Result)
			if testCase.wantResult == auth.ResultSuccess {
				require.NoError(t, outcome.Err)
				require.Equal(t, testCase.wantSubject, outcome.Identity.Subject)
				return
			}
			require.Error(t, outcome.Err)
			require.Nil(t, outcome.Identity)
			require.Equal(t, testCase.wantCode, recorder.Code)
			status, _ := auth.ResponseFor(outcome.Err)
			require.Equal(t, testCase.wantCode, status)
		})
	}
}

func TestObserverReceivesRequestContext(t *testing.T) {
	var got any
	authenticator := newStatic(t, apikey.Options{Observer: func(ctx context.Context, _ auth.Outcome) { got = ctx.Value(contextKey{}) }})
	request := httptest.NewRequestWithContext(context.WithValue(t.Context(), contextKey{}, "request-scoped"), http.MethodGet, "/", nil)
	request.Header.Set("X-API-Key", buildSecret)

	serve(authenticator, request)

	require.Equal(t, "request-scoped", got)
}
