package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

const impersonationPath = "/auth/impersonation"

var (
	testAdminID  = uuid.MustParse("0b6f2c1e-7a3d-4c55-9f0e-2d8b1a6c4e71")
	testTargetID = uuid.MustParse("5d0f3b9a-2c4e-4f61-8a7b-9e1d2c3b4a50")
)

func testAdmin() *auth.Identity {
	return &auth.Identity{Provider: "password", Subject: "admin-1", UserID: testAdminID, Username: "grace", Active: true, Roles: []string{auth.RoleAdmin}}
}

// testTargets are what the fixture's loader returns per subject; a subject it does not list has no identity.
func testTargets() map[string]*auth.Identity {
	return map[string]*auth.Identity{
		"user-2":     {Provider: "password", Subject: "user-2", UserID: testTargetID, Username: "ada", Active: true, Roles: []string{"reader"}},
		"user-3":     {Provider: "password", Subject: "user-3", Active: true},
		"inactive":   {Provider: "password", Subject: "inactive", Active: false},
		"admin-2":    {Provider: "password", Subject: "admin-2", Active: true, Roles: []string{auth.RoleAdmin}},
		"admin-1":    testAdmin(),
		"same-user":  {Provider: "github", Subject: "42", UserID: testAdminID, Active: true},
		"rogue":      {Provider: "password", Subject: "rogue", Active: true, Impersonator: &auth.Identity{Provider: "password", Subject: "x", Active: true}},
		"tenant-b":   nil, // the loader refuses it
		"loader-bug": nil, // the loader fails
	}
}

var errLoaderDown = errors.New("user directory down")

type impersonationFixture struct {
	*guardFixture
	impersonator *Impersonator
	serveMux     *http.ServeMux
}

func newImpersonationFixture(t *testing.T, guardOptions GuardOptions, options ImpersonatorOptions) *impersonationFixture {
	t.Helper()
	fixture := &impersonationFixture{guardFixture: newGuardFixture(t, guardOptions), serveMux: http.NewServeMux()}
	targets := testTargets()
	options.Guard = fixture.guard
	options.Observer = fixture.observer.observe
	options.Load = func(_ context.Context, subject string) (*auth.Identity, error) {
		switch subject {
		case "tenant-b":
			return nil, &auth.Error{Kind: auth.ErrForbidden, Code: "other_tenant"}
		case "loader-bug":
			return nil, errLoaderDown
		}
		return targets[subject].Clone(), nil
	}
	impersonator, err := NewImpersonator(&options)
	require.NoError(t, err)
	fixture.impersonator = impersonator
	auth.RegisterRoutes(fixture.serveMux, impersonator.Routes())
	return fixture
}

// impersonate starts impersonating subject in the session request carries, as the route would.
func (f *impersonationFixture) impersonate(t *testing.T, request *http.Request, subject string) *auth.Identity {
	t.Helper()
	impersonated, err := f.impersonator.Start(withSessionIdentity(t, f.store, request), subject)
	require.NoError(t, err)
	return impersonated
}

// serve sends method to the impersonation route with the cookies of request and body (none when empty).
func (f *impersonationFixture) serve(t *testing.T, method string, request *http.Request, body string) *httptest.ResponseRecorder {
	t.Helper()
	routed := httptest.NewRequestWithContext(t.Context(), method, impersonationPath, bytes.NewBufferString(body))
	if body != "" {
		routed.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range request.Cookies() {
		routed.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	f.serveMux.ServeHTTP(recorder, routed)
	return recorder
}

// storedIdentity returns the identity the session of request holds.
func storedIdentity(t *testing.T, store *Store, request *http.Request) *auth.Identity {
	t.Helper()
	current, err := store.Open(request)
	require.NoError(t, err)
	identity, err := current.Identity(t.Context())
	require.NoError(t, err)
	return identity
}

// withSessionIdentity returns request with the identity of its session in its context, as the Guard puts it.
func withSessionIdentity(t *testing.T, store *Store, request *http.Request) *http.Request {
	t.Helper()
	return request.WithContext(auth.WithIdentity(request.Context(), storedIdentity(t, store, request)))
}

func decodeIdentityResponse(t *testing.T, recorder *httptest.ResponseRecorder) auth.IdentityResponse {
	t.Helper()
	var response auth.IdentityResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	return response
}

func requireCode(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	require.Equal(t, wantStatus, recorder.Code, recorder.Body.String())
	var response auth.ErrorResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Equal(t, wantCode, response.Code)
}

func TestNewImpersonatorValidation(t *testing.T) {
	guard, err := NewGuard(&GuardOptions{Store: newTestStore(t, newTestClock())})
	require.NoError(t, err)
	load := func(context.Context, string) (*auth.Identity, error) { return nil, nil }
	testCases := []struct {
		name    string
		options *ImpersonatorOptions
		want    string
	}{
		{name: "nil options", want: "Guard and Load are required"},
		{name: "no Guard", options: &ImpersonatorOptions{Load: load}, want: "Guard and Load are required"},
		{name: "no Load", options: &ImpersonatorOptions{Guard: guard}, want: "Guard and Load are required"},
		{name: "short MaximumDuration", options: &ImpersonatorOptions{Guard: guard, Load: load, MaximumDuration: time.Millisecond}, want: "below one second"},
		{name: "relative PathPrefix", options: &ImpersonatorOptions{Guard: guard, Load: load, PathPrefix: "auth/impersonation"}, want: "PathPrefix"},
		{name: "trailing slash", options: &ImpersonatorOptions{Guard: guard, Load: load, PathPrefix: "/auth/"}, want: "PathPrefix"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewImpersonator(testCase.options)
			require.ErrorContains(t, err, testCase.want)
		})
	}
	impersonator, err := NewImpersonator(&ImpersonatorOptions{Guard: guard, Load: load})
	require.NoError(t, err)
	require.Equal(t, []string{"POST " + impersonationPath, "DELETE " + impersonationPath}, routePatterns(impersonator.Routes()))
	require.Equal(t, time.Hour, impersonator.options.MaximumDuration)
}

func routePatterns(routes []auth.Route) []string {
	patterns := make([]string, 0, len(routes))
	for _, route := range routes {
		patterns = append(patterns, route.Method+" "+route.Path)
	}
	return patterns
}

func TestImpersonatorStartsAndStopsInTheSameSession(t *testing.T) {
	fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{})
	request := login(t, fixture.store, testAdmin())
	fixture.observer.take()

	started := fixture.serve(t, http.MethodPost, request, `{"subject":"user-2"}`)

	require.Equal(t, http.StatusOK, started.Code, started.Body.String())
	require.Empty(t, started.Header().Values("Set-Cookie"), "the session and its cookie stay")
	response := decodeIdentityResponse(t, started)
	require.Equal(t, "user-2", response.Subject)
	require.Equal(t, "admin-1", response.Impersonator.Subject)
	want := testTargets()["user-2"]
	want.Impersonator = testAdmin()
	require.Equal(t, want, serveGuarded(fixture.guard.RequireAPI(), request).identity)
	outcomes := fixture.observer.take()
	require.Equal(t, auth.Outcome{Provider: "password", Action: auth.ActionImpersonationStart, Result: auth.ResultSuccess, Identity: want}, outcomes[len(outcomes)-2])

	stopped := fixture.serve(t, http.MethodDelete, request, "")

	require.Equal(t, http.StatusOK, stopped.Code, stopped.Body.String())
	require.Equal(t, auth.NewIdentityResponse(testAdmin()), decodeIdentityResponse(t, stopped))
	require.Equal(t, testAdmin(), serveGuarded(fixture.guard.RequireAPI(), request).identity)
	outcomes = fixture.observer.take()
	require.Equal(t, auth.Outcome{Provider: "password", Action: auth.ActionImpersonationStop, Result: auth.ResultSuccess, Identity: want}, outcomes[len(outcomes)-2])
	require.Equal(t, http.StatusOK, fixture.serve(t, http.MethodPost, request, `{"subject":"user-3"}`).Code, "a stopped impersonation can be followed by another")
}

func TestImpersonatorStartRefusals(t *testing.T) {
	testCases := []struct {
		name        string
		identity    *auth.Identity // logged in; nil: no session
		impersonate string         // impersonated first; empty: none
		options     ImpersonatorOptions
		body        string
		wantStatus  int
		wantCode    string
	}{
		{name: "no session", body: `{"subject":"user-2"}`, wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated"},
		{name: "not an admin", identity: testTargets()["user-3"], body: `{"subject":"user-2"}`, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{
			name: "inactive", identity: &auth.Identity{Provider: "password", Subject: "admin-1", Active: false}, options: ImpersonatorOptions{Actor: func(context.Context) error { return nil }},
			body: `{"subject":"user-2"}`, wantStatus: http.StatusForbidden, wantCode: "forbidden",
		},
		{name: "own actor check", identity: testAdmin(), options: ImpersonatorOptions{Actor: func(context.Context) error {
			return &auth.Error{Kind: auth.ErrForbidden, Code: "support_only"}
		}}, body: `{"subject":"user-2"}`, wantStatus: http.StatusForbidden, wantCode: "support_only"},
		{name: "already impersonating", identity: testAdmin(), impersonate: "user-2", body: `{"subject":"user-3"}`, wantStatus: http.StatusConflict, wantCode: "already_impersonating"},
		{name: "empty subject", identity: testAdmin(), body: `{"subject":""}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "malformed body", identity: testAdmin(), body: `{"subject":1}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown target", identity: testAdmin(), body: `{"subject":"nobody"}`, wantStatus: http.StatusBadRequest, wantCode: "unknown_impersonation_target"},
		{name: "self", identity: testAdmin(), body: `{"subject":"admin-1"}`, wantStatus: http.StatusBadRequest, wantCode: "self_impersonation"},
		{name: "self by user ID", identity: testAdmin(), body: `{"subject":"same-user"}`, wantStatus: http.StatusBadRequest, wantCode: "self_impersonation"},
		{name: "inactive target", identity: testAdmin(), options: ImpersonatorOptions{Target: func(context.Context) error { return nil }}, body: `{"subject":"inactive"}`, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "admin target", identity: testAdmin(), body: `{"subject":"admin-2"}`, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "loader refusal", identity: testAdmin(), body: `{"subject":"tenant-b"}`, wantStatus: http.StatusForbidden, wantCode: "other_tenant"},
		{name: "loader failure", identity: testAdmin(), body: `{"subject":"loader-bug"}`, wantStatus: http.StatusInternalServerError, wantCode: "internal"},
		{name: "loaded identity impersonates", identity: testAdmin(), body: `{"subject":"rogue"}`, wantStatus: http.StatusInternalServerError, wantCode: "internal"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newImpersonationFixture(t, GuardOptions{}, testCase.options)
			request := newRequest(t)
			if testCase.identity != nil {
				request = login(t, fixture.store, testCase.identity)
			}
			if testCase.impersonate != "" {
				fixture.impersonate(t, request, testCase.impersonate)
			}
			var before *auth.Identity
			if testCase.identity != nil {
				before = storedIdentity(t, fixture.store, request)
			}
			fixture.observer.take()

			recorder := fixture.serve(t, http.MethodPost, request, testCase.body)

			requireCode(t, recorder, testCase.wantStatus, testCase.wantCode)
			if testCase.identity == nil {
				return
			}
			require.Equal(t, before, storedIdentity(t, fixture.store, request), "the session is unchanged")
			outcomes := fixture.observer.take()
			outcome := outcomes[len(outcomes)-1]
			require.Equal(t, auth.ActionImpersonationStart, outcome.Action)
			require.Contains(t, []auth.Result{auth.ResultDenied, auth.ResultError}, outcome.Result)
			require.Equal(t, before, outcome.Identity)
		})
	}
}

func TestImpersonatorStopRefusals(t *testing.T) {
	fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{})

	requireCode(t, fixture.serve(t, http.MethodDelete, newRequest(t), ""), http.StatusUnauthorized, "unauthenticated")
	requireCode(t, fixture.serve(t, http.MethodDelete, login(t, fixture.store, testAdmin()), ""), http.StatusConflict, "not_impersonating")
	_, err := fixture.impersonator.Stop(newRequest(t))
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "without the Guard's identity")
}

// Start and Stop replace the identity the Guard read only while the session still holds it.
func TestImpersonatorRefusesASessionChangedMeanwhile(t *testing.T) {
	fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{})
	request := login(t, fixture.store, testAdmin())
	read := withSessionIdentity(t, fixture.store, request)
	current, err := fixture.store.Open(request)
	require.NoError(t, err)
	changed := testAdmin()
	changed.Username = "renamed"
	require.NoError(t, current.SaveIdentity(t.Context(), changed))

	_, err = fixture.impersonator.Start(read, "user-2")

	require.ErrorIs(t, err, auth.ErrConflict)
	require.Equal(t, changed, storedIdentity(t, fixture.store, request))

	impersonated := fixture.impersonate(t, request, "user-2")
	stale := withSessionIdentity(t, fixture.store, request)
	demoted := impersonated.Clone()
	demoted.Impersonator.Roles = nil
	swapped, err := current.SwapIdentity(t.Context(), impersonated, demoted)
	require.NoError(t, err)
	require.True(t, swapped)

	_, err = fixture.impersonator.Stop(stale)

	require.ErrorIs(t, err, auth.ErrConflict)
	require.Equal(t, demoted, storedIdentity(t, fixture.store, request))
}

func TestImpersonationEndsAfterMaximumDuration(t *testing.T) {
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		refreshed := identity.Clone()
		refreshed.Username = "grace hopper"
		return refreshed, nil
	}}
	fixture := newImpersonationFixture(t, GuardOptions{Refreshers: []Refresher{refresher}}, ImpersonatorOptions{MaximumDuration: 10 * time.Minute})
	request := login(t, fixture.store, testAdmin())
	fixture.impersonate(t, request, "user-2")

	fixture.clock.advance(10*time.Minute - time.Second)
	require.Equal(t, "user-2", serveGuarded(fixture.guard.RequireAPI(), request).identity.Subject)
	fixture.clock.advance(time.Second)
	result := serveGuarded(fixture.guard.RequireAPI(), request)

	want := testAdmin()
	want.Username = "grace hopper"
	require.Equal(t, want, result.identity, "the impersonator, as refreshed meanwhile")
	require.Equal(t, want, storedIdentity(t, fixture.store, request))
	require.Equal(t, http.StatusOK, fixture.serve(t, http.MethodPost, request, `{"subject":"user-3"}`).Code, "a new impersonation can start")
}

func TestImpersonationEndsWithTheSession(t *testing.T) {
	fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{})
	request := login(t, fixture.store, testAdmin())
	fixture.clock.advance(24*time.Hour - time.Minute)
	fixture.impersonate(t, request, "user-2")

	fixture.clock.advance(time.Minute + time.Second)

	require.Equal(t, http.StatusUnauthorized, serveGuarded(fixture.guard.RequireAPI(), request).recorder.Code, "no new lifetime")
}

// An impersonation saved without an end (by application code before the Impersonator existed), nested ones
// included, ends at the next request, in favour of the identity that authenticated.
func TestGuardEndsAnImpersonationWithoutAnEnd(t *testing.T) {
	fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{})
	request := login(t, fixture.store, testAdmin())
	current, err := fixture.store.Open(request)
	require.NoError(t, err)
	stored, err := current.envelope(t.Context())
	require.NoError(t, err)
	stored.Identity = &auth.Identity{Provider: "password", Subject: "user-3", Active: true, Impersonator: &auth.Identity{
		Provider: "password", Subject: "user-2", Active: true, Impersonator: testAdmin(),
	}}
	_, swapped, err := current.swapEnvelope(t.Context(), stored)
	require.NoError(t, err)
	require.True(t, swapped)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, testAdmin(), result.identity)
	require.Equal(t, testAdmin(), storedIdentity(t, fixture.store, request))
}

func TestGuardAnswersAFailedImpersonationEndWith500(t *testing.T) {
	fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{MaximumDuration: time.Minute})
	request := login(t, fixture.store, testAdmin())
	fixture.impersonate(t, request, "user-2")
	fixture.clock.advance(time.Minute)
	fixture.store.options.Backend = &swapFailingBackend{Backend: fixture.store.options.Backend}

	require.Equal(t, http.StatusInternalServerError, serveGuarded(fixture.guard.RequireAPI(), request).recorder.Code)
}

// Only the Impersonator starts, stops or changes an impersonation; saves keep the session's principals.
func TestSavesKeepTheSessionsPrincipals(t *testing.T) {
	fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{})
	ctx := t.Context()
	started, _ := startSession(t, fixture.store)
	impersonating := testTargets()["user-2"]
	impersonating.Impersonator = testAdmin()
	require.ErrorContains(t, started.SaveIdentity(ctx, impersonating), "a login cannot impersonate")

	request := login(t, fixture.store, testAdmin())
	current, err := fixture.store.Open(request)
	require.NoError(t, err)
	other := testAdmin()
	other.Subject = "admin-2"
	require.ErrorContains(t, current.SaveIdentity(ctx, other), "keep their provider and subject", "another user")
	require.ErrorContains(t, current.SaveIdentity(ctx, impersonating), "keep their provider and subject", "starting an impersonation")
	_, err = current.SwapIdentity(ctx, testAdmin(), impersonating)
	require.ErrorContains(t, err, "keep their provider and subject", "starting an impersonation")

	impersonated := fixture.impersonate(t, request, "user-2")
	_, err = current.SwapIdentity(ctx, impersonated, testAdmin())
	require.ErrorContains(t, err, "keep their provider and subject", "stopping an impersonation")
	otherImpersonator := impersonated.Clone()
	otherImpersonator.Impersonator.Subject = "admin-2"
	_, err = current.SwapIdentity(ctx, impersonated, otherImpersonator)
	require.ErrorContains(t, err, "keep their provider and subject", "another impersonator")
	otherTarget := impersonated.Clone()
	otherTarget.Subject = "user-3"
	require.ErrorContains(t, current.SaveIdentity(ctx, otherTarget), "keep their provider and subject", "another target")

	demoted := impersonated.Clone()
	demoted.Impersonator.Roles = nil
	swapped, err := current.SwapIdentity(ctx, impersonated, demoted)
	require.NoError(t, err, "the real identity may change")
	require.True(t, swapped)
	fixture.clock.advance(time.Hour)
	require.Equal(t, demoted.Impersonator, serveGuarded(fixture.guard.RequireAPI(), request).identity, "a save keeps the impersonation's end")
}

func TestGuardEndingAnImpersonationLosesToAConcurrentSave(t *testing.T) {
	testCases := []struct {
		name       string
		save       func(stored identityEnvelope) identityEnvelope // what the other request saves
		wantStatus int
	}{
		{name: "the other request ended it", save: func(stored identityEnvelope) identityEnvelope {
			stored.Identity, stored.ImpersonationEndsAt = stored.Identity.Impersonator, time.Time{}
			return stored
		}, wantStatus: http.StatusNoContent},
		{name: "the other request saved it unended", save: func(stored identityEnvelope) identityEnvelope {
			stored.Identity = stored.Identity.Clone()
			stored.Identity.Username = "renamed"
			return stored
		}, wantStatus: http.StatusConflict},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{MaximumDuration: time.Minute})
			request := login(t, fixture.store, testAdmin())
			fixture.impersonate(t, request, "user-2")
			fixture.clock.advance(time.Minute)
			current, err := fixture.store.Open(request)
			require.NoError(t, err)
			backend := &beforeSwapBackend{Backend: fixture.store.options.Backend}
			backend.beforeSwap = func() {
				stored, err := current.envelope(t.Context())
				require.NoError(t, err)
				_, swapped, err := current.swapEnvelope(t.Context(), testCase.save(stored))
				require.NoError(t, err)
				require.True(t, swapped)
			}
			fixture.store.options.Backend = backend

			result := serveGuarded(fixture.guard.RequireAPI(), request)

			require.Equal(t, testCase.wantStatus, result.recorder.Code)
			if testCase.wantStatus == http.StatusNoContent {
				require.Equal(t, testAdmin(), result.identity)
			}
		})
	}
}

func TestImpersonatorWithoutAUsableSession(t *testing.T) {
	fixture := newImpersonationFixture(t, GuardOptions{}, ImpersonatorOptions{})
	impersonating := testTargets()["user-2"]
	impersonating.Impersonator = testAdmin()

	_, err := fixture.impersonator.Start(newRequest(t), "user-2")
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "no identity in the context")
	_, err = fixture.impersonator.Start(withSessionIdentityOf(newRequest(t), testAdmin()), "user-2")
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "an identity without a session cookie (an API key)")
	_, err = fixture.impersonator.Stop(withSessionIdentityOf(newRequest(t), impersonating))
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "an identity without a session cookie")

	request := login(t, fixture.store, testAdmin())
	read := withSessionIdentity(t, fixture.store, request)
	require.NoError(t, fixture.store.End(t.Context(), httptest.NewRecorder(), request))
	_, err = fixture.impersonator.Start(read, "user-2")
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "an ended session")

	failing := login(t, fixture.store, testAdmin())
	fixture.store.options.Backend = &swapFailingBackend{Backend: fixture.store.options.Backend}
	_, err = fixture.impersonator.Start(withSessionIdentity(t, fixture.store, failing), "user-2")
	require.ErrorIs(t, err, errBackendDown)
}

func withSessionIdentityOf(request *http.Request, identity *auth.Identity) *http.Request {
	return request.WithContext(auth.WithIdentity(request.Context(), identity))
}
