package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

// fakeRefresher answers Refresh with refresh and records the identities it was called with.
type fakeRefresher struct {
	name    string
	refresh func(identity *auth.Identity) (*auth.Identity, error)
	mutex   sync.Mutex
	calls   []*auth.Identity
}

func (r *fakeRefresher) Name() string {
	return r.name
}

func (r *fakeRefresher) Refresh(_ context.Context, _ Session, identity *auth.Identity) (*auth.Identity, error) {
	r.mutex.Lock()
	r.calls = append(r.calls, identity.Clone())
	r.mutex.Unlock()
	return r.refresh(identity)
}

func (r *fakeRefresher) callCount() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return len(r.calls)
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

func (r *outcomeRecorder) take() []auth.Outcome {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	outcomes := r.outcomes
	r.outcomes = nil
	return outcomes
}

type guardFixture struct {
	clock    *testClock
	store    *Store
	guard    *Guard
	observer *outcomeRecorder
}

func newGuardFixture(t *testing.T, options GuardOptions) *guardFixture {
	t.Helper()
	clock := newTestClock()
	fixture := &guardFixture{clock: clock, store: newTestStore(t, clock), observer: &outcomeRecorder{}}
	options.Store = fixture.store
	options.Observer = fixture.observer.observe
	guard, err := NewGuard(&options)
	require.NoError(t, err)
	guard.now = clock.now
	fixture.guard = guard
	return fixture
}

type guardResult struct {
	recorder *httptest.ResponseRecorder
	identity *auth.Identity // seen by the next handler; nil when it did not run
}

func serveGuarded(middleware func(http.Handler) http.Handler, request *http.Request) guardResult {
	var result guardResult
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result.identity = auth.IdentityFrom(request.Context())
		writer.WriteHeader(http.StatusNoContent)
	})
	result.recorder = httptest.NewRecorder()
	middleware(next).ServeHTTP(result.recorder, request)
	return result
}

func TestNewGuardValidation(t *testing.T) {
	store := newTestStore(t, newTestClock())
	refresher := &fakeRefresher{name: "password"}
	testCases := []struct {
		name      string
		options   *GuardOptions
		wantError string
	}{
		{name: "nil options", wantError: "Store is required"},
		{name: "no store", options: &GuardOptions{}, wantError: "Store is required"},
		{name: "relative login URL", options: &GuardOptions{Store: store, LoginURL: "login"}, wantError: "LoginURL must be"},
		{name: "protocol relative login URL", options: &GuardOptions{Store: store, LoginURL: "//evil.example/login"}, wantError: "LoginURL must be"},
		{name: "backslash login URL", options: &GuardOptions{Store: store, LoginURL: "/\\evil.example"}, wantError: "LoginURL must be"},
		{name: "other scheme", options: &GuardOptions{Store: store, LoginURL: "ftp://example.com/login"}, wantError: "LoginURL must be"},
		{name: "absolute URL without host", options: &GuardOptions{Store: store, LoginURL: "https:///login"}, wantError: "LoginURL must be"},
		{name: "login URL with a fragment", options: &GuardOptions{Store: store, LoginURL: "https://auth.example.com/login#/signin"}, wantError: "without a fragment"},
		{name: "negative refresh interval", options: &GuardOptions{Store: store, RefreshInterval: -time.Second}, wantError: "RefreshInterval -1s is negative"},
		{name: "maximum unverified age below the refresh interval", options: &GuardOptions{Store: store, RefreshInterval: time.Hour, MaximumUnverifiedAge: time.Minute}, wantError: "MaximumUnverifiedAge 1m0s is below RefreshInterval 1h0m0s"},
		{name: "nil refresher", options: &GuardOptions{Store: store, Refreshers: []Refresher{nil}}, wantError: "every Refresher needs a name"},
		{name: "unnamed refresher", options: &GuardOptions{Store: store, Refreshers: []Refresher{&fakeRefresher{}}}, wantError: "every Refresher needs a name"},
		{name: "duplicate refresher names", options: &GuardOptions{Store: store, Refreshers: []Refresher{refresher, &fakeRefresher{name: "password"}}}, wantError: `two Refreshers are named "password"`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			guard, err := NewGuard(testCase.options)
			require.ErrorContains(t, err, testCase.wantError)
			require.Nil(t, guard)
		})
	}
}

func TestNewGuardDefaultsOnACopy(t *testing.T) {
	refresher := &fakeRefresher{name: "password"}
	store := newTestStore(t, newTestClock())
	options := &GuardOptions{Store: store, Refreshers: []Refresher{refresher}}

	guard, err := NewGuard(options)
	options.Refreshers[0] = &fakeRefresher{name: "github"}

	require.NoError(t, err)
	require.Empty(t, options.LoginURL, "caller's options untouched")
	require.Zero(t, options.RefreshInterval, "caller's options untouched")
	require.Equal(t, "/", guard.options.LoginURL)
	require.Equal(t, time.Minute, guard.options.RefreshInterval)
	require.Equal(t, time.Hour, guard.options.MaximumUnverifiedAge)
	require.Equal(t, map[string]Refresher{"password": refresher}, guard.refreshers)
	slowGuard, err := NewGuard(&GuardOptions{Store: store, RefreshInterval: 2 * time.Hour})
	require.NoError(t, err)
	require.Equal(t, 2*time.Hour, slowGuard.options.MaximumUnverifiedAge, "the default never undercuts the interval")

	for _, loginURL := range []string{"/login", "/login?provider=oidc", "http://localhost:8080/login", "https://auth.example.com/auth/oidc/oidc/login"} {
		_, err := NewGuard(&GuardOptions{Store: store, LoginURL: loginURL})
		require.NoError(t, err, loginURL)
	}
}

func TestGuardPassesARequestThatCarriesAnIdentity(t *testing.T) {
	fixture := newGuardFixture(t, GuardOptions{})
	identity := &auth.Identity{Provider: "apikey", Subject: "ci", Active: true}
	request := httptest.NewRequestWithContext(auth.WithIdentity(t.Context(), identity), http.MethodGet, "/api", nil)

	for _, middleware := range []func(http.Handler) http.Handler{fixture.guard.RequireAPI(), fixture.guard.RequireUI()} {
		result := serveGuarded(middleware, request)

		require.Equal(t, http.StatusNoContent, result.recorder.Code)
		require.Same(t, identity, result.identity)
	}
	require.Empty(t, fixture.observer.take(), "nothing reported")
}

func TestGuardRefusesRequestsWithoutAnIdentity(t *testing.T) {
	testCases := []struct {
		name    string
		request func(t *testing.T, fixture *guardFixture) *http.Request
	}{
		{name: "no cookie", request: func(t *testing.T, _ *guardFixture) *http.Request {
			return newRequest(t)
		}},
		{name: "malformed cookie", request: func(t *testing.T, _ *guardFixture) *http.Request {
			request := newRequest(t)
			request.Header.Set("Cookie", "__Host-auth_session=forged")
			return request
		}},
		{name: "session without identity", request: func(t *testing.T, fixture *guardFixture) *http.Request {
			_, request := startSession(t, fixture.store)
			return request
		}},
		{name: "ended session", request: func(t *testing.T, fixture *guardFixture) *http.Request {
			request := login(t, fixture.store, testIdentity())
			require.NoError(t, fixture.store.End(t.Context(), httptest.NewRecorder(), request))
			return request
		}},
		{name: "expired session", request: func(t *testing.T, fixture *guardFixture) *http.Request {
			request := login(t, fixture.store, testIdentity())
			fixture.clock.advance(24*time.Hour + time.Second)
			return request
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newGuardFixture(t, GuardOptions{LoginURL: "/login"})
			request := testCase.request(t, fixture)

			api := serveGuarded(fixture.guard.RequireAPI(), request)
			ui := serveGuarded(fixture.guard.RequireUI(), request)

			require.Equal(t, http.StatusUnauthorized, api.recorder.Code)
			require.JSONEq(t, `{"code":"unauthenticated","message":"authentication required"}`, api.recorder.Body.String())
			require.Equal(t, "no-store", api.recorder.Header().Get("Cache-Control"))
			require.Nil(t, api.identity)
			require.Equal(t, http.StatusFound, ui.recorder.Code)
			require.Equal(t, "/login?return_to=%2F", ui.recorder.Header().Get("Location"))
			require.Equal(t, "no-store", ui.recorder.Header().Get("Cache-Control"))
			require.Nil(t, ui.identity)
			for _, outcome := range fixture.observer.take() {
				require.Equal(t, "session", outcome.Provider)
				require.Equal(t, auth.ActionAuthenticate, outcome.Action)
				require.Equal(t, auth.ResultDenied, outcome.Result)
				require.ErrorIs(t, outcome.Err, auth.ErrUnauthenticated)
				require.Nil(t, outcome.Identity)
			}
		})
	}
}

func TestGuardRequireUIRedirectsWithTheReturnPath(t *testing.T) {
	testCases := []struct {
		name         string
		options      GuardOptions
		target       string
		header       string
		wantLocation string
	}{
		{name: "request URI", options: GuardOptions{LoginURL: "/login"}, target: "/dashboard?tab=2", wantLocation: "/login?return_to=%2Fdashboard%3Ftab%3D2"},
		{name: "default login URL", target: "/dashboard", wantLocation: "/?return_to=%2Fdashboard"},
		{name: "login URL with query", options: GuardOptions{LoginURL: "https://auth.example.com/login?provider=oidc"}, target: "/a", wantLocation: "https://auth.example.com/login?provider=oidc&return_to=%2Fa"},
		{name: "forwarded URI header", options: GuardOptions{LoginURL: "https://auth.example.com/login", ReturnPathHeader: "X-Forwarded-Uri"}, target: "/auth/ui", header: "/app?x=1", wantLocation: "https://auth.example.com/login?return_to=%2Fapp%3Fx%3D1"},
		{name: "unsafe forwarded URI omitted", options: GuardOptions{LoginURL: "/login", ReturnPathHeader: "X-Forwarded-Uri"}, target: "/auth/ui", header: "//evil.example", wantLocation: "/login"},
		{name: "missing forwarded URI omitted", options: GuardOptions{LoginURL: "/login", ReturnPathHeader: "X-Forwarded-Uri"}, target: "/auth/ui", wantLocation: "/login"},
		{name: "unsafe request URI omitted", options: GuardOptions{LoginURL: "/login"}, target: "//evil.example/x", wantLocation: "/login"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newGuardFixture(t, testCase.options)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://app.example.com"+testCase.target, nil)
			if testCase.header != "" {
				request.Header.Set("X-Forwarded-Uri", testCase.header)
			}

			result := serveGuarded(fixture.guard.RequireUI(), request)

			require.Equal(t, http.StatusFound, result.recorder.Code)
			require.Equal(t, testCase.wantLocation, result.recorder.Header().Get("Location"))
			require.Empty(t, result.recorder.Body.String())
		})
	}
}

func TestGuardAuthenticates(t *testing.T) {
	fixture := newGuardFixture(t, GuardOptions{})
	request := login(t, fixture.store, testIdentity())

	for _, middleware := range []func(http.Handler) http.Handler{fixture.guard.RequireAPI(), fixture.guard.RequireUI()} {
		result := serveGuarded(middleware, request)

		require.Equal(t, http.StatusNoContent, result.recorder.Code)
		require.Equal(t, testIdentity(), result.identity)
		require.Equal(t, []auth.Outcome{
			{Provider: "password", Action: auth.ActionAuthenticate, Result: auth.ResultSuccess, Identity: testIdentity()},
		}, fixture.observer.take())
	}
}

func TestGuardAnswersABackendFailureWith500(t *testing.T) {
	clock := newTestClock()
	request := login(t, newTestStore(t, clock), testIdentity())
	observer := &outcomeRecorder{}
	guard, err := NewGuard(&GuardOptions{Store: newTestStoreOn(t, clock, failingBackend{}), Observer: observer.observe})
	require.NoError(t, err)

	for _, middleware := range []func(http.Handler) http.Handler{guard.RequireAPI(), guard.RequireUI()} {
		result := serveGuarded(middleware, request)

		require.Equal(t, http.StatusInternalServerError, result.recorder.Code)
		require.JSONEq(t, `{"code":"internal","message":"internal error"}`, result.recorder.Body.String())
		outcomes := observer.take()
		require.Len(t, outcomes, 1)
		require.Equal(t, auth.ResultError, outcomes[0].Result)
		require.ErrorIs(t, outcomes[0].Err, errBackendDown)
	}
}

func TestGuardRefreshesAfterTheInterval(t *testing.T) {
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		refreshed := identity.Clone()
		refreshed.Username = "ada-renamed"
		return refreshed, nil
	}}
	fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request := login(t, fixture.store, testIdentity())
	want := testIdentity()
	want.Username = "ada-renamed"

	fixture.clock.advance(time.Minute)
	result := serveGuarded(fixture.guard.RequireAPI(), request)
	require.Equal(t, http.StatusNoContent, result.recorder.Code)
	require.Equal(t, testIdentity(), result.identity, "not due at exactly the interval")
	require.Zero(t, refresher.callCount())
	fixture.observer.take()

	fixture.clock.advance(time.Second)
	result = serveGuarded(fixture.guard.RequireAPI(), request)
	require.Equal(t, http.StatusNoContent, result.recorder.Code)
	require.Equal(t, want, result.identity)
	require.Equal(t, []*auth.Identity{testIdentity()}, refresher.calls)
	require.Equal(t, []auth.Outcome{
		{Provider: "password", Action: auth.ActionRefresh, Result: auth.ResultSuccess, Identity: want},
		{Provider: "password", Action: auth.ActionAuthenticate, Result: auth.ResultSuccess, Identity: want},
	}, fixture.observer.take())

	result = serveGuarded(fixture.guard.RequireAPI(), request)
	require.Equal(t, want, result.identity, "the refreshed identity was saved")
	require.Equal(t, 1, refresher.callCount(), "refreshedAt moved")
}

func TestGuardRefreshesTheImpersonator(t *testing.T) {
	impersonated := &auth.Identity{
		Provider: "password", Subject: "user-2", Active: true,
		Impersonator: &auth.Identity{Provider: "password", Subject: "admin-1", Active: true, Roles: []string{auth.RoleAdmin}},
	}
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		refreshed := identity.Clone()
		refreshed.Roles = nil
		return refreshed, nil
	}}
	fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request := login(t, fixture.store, impersonated)
	fixture.clock.advance(2 * time.Minute)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, []*auth.Identity{impersonated.Impersonator}, refresher.calls, "called with the real identity")
	require.Equal(t, "user-2", result.identity.Subject)
	require.Equal(t, "admin-1", result.identity.Impersonator.Subject)
	require.Empty(t, result.identity.Impersonator.Roles)
}

func TestGuardRefreshOnlyForProvidersWithARefresher(t *testing.T) {
	refresher := &fakeRefresher{name: "github"}
	fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request := login(t, fixture.store, testIdentity())
	fixture.clock.advance(time.Hour)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, http.StatusNoContent, result.recorder.Code)
	require.Zero(t, refresher.callCount())
}

func TestGuardRefreshRefusalEndsTheSession(t *testing.T) {
	testCases := []struct {
		name         string
		refusal      error
		wantAPI      int
		wantUI       int
		wantAPIError string
	}{
		{name: "unauthenticated", refusal: &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "user deleted"}, wantAPI: http.StatusUnauthorized, wantUI: http.StatusFound, wantAPIError: `{"code":"unauthenticated","message":"authentication required"}`},
		{name: "forbidden", refusal: &auth.Error{Kind: auth.ErrForbidden, Reason: "not in an allowed team"}, wantAPI: http.StatusForbidden, wantUI: http.StatusForbidden, wantAPIError: `{"code":"forbidden","message":"access denied"}`},
		{name: "bare sentinel", refusal: auth.ErrForbidden, wantAPI: http.StatusForbidden, wantUI: http.StatusForbidden, wantAPIError: `{"code":"forbidden","message":"access denied"}`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			refresher := &fakeRefresher{name: "password", refresh: func(*auth.Identity) (*auth.Identity, error) {
				return nil, testCase.refusal
			}}
			fixture := newGuardFixture(t, GuardOptions{LoginURL: "/login", Refreshers: []Refresher{refresher}})
			apiRequest := login(t, fixture.store, testIdentity())
			uiRequest := login(t, fixture.store, testIdentity())
			fixture.clock.advance(2 * time.Minute)

			api := serveGuarded(fixture.guard.RequireAPI(), apiRequest)
			ui := serveGuarded(fixture.guard.RequireUI(), uiRequest)

			require.Equal(t, testCase.wantAPI, api.recorder.Code)
			require.JSONEq(t, testCase.wantAPIError, api.recorder.Body.String())
			require.Equal(t, testCase.wantUI, ui.recorder.Code)
			for _, result := range []guardResult{api, ui} {
				require.Nil(t, result.identity)
				requireExpiredCookie(t, result.recorder)
			}
			for _, request := range []*http.Request{apiRequest, uiRequest} {
				current, err := fixture.store.Open(request)
				require.NoError(t, err)
				_, err = current.Identity(t.Context())
				require.ErrorIs(t, err, auth.ErrUnauthenticated, "session ended")
			}
			outcomes := fixture.observer.take()
			require.Len(t, outcomes, 2)
			for _, outcome := range outcomes {
				require.Equal(t, auth.ActionRefresh, outcome.Action)
				require.Equal(t, auth.ResultDenied, outcome.Result)
				require.ErrorIs(t, outcome.Err, testCase.refusal)
				require.Equal(t, testIdentity(), outcome.Identity)
			}
		})
	}
}

// revokeFailingBackend fails every Revoke and passes everything else on.
type revokeFailingBackend struct {
	Backend
}

func (revokeFailingBackend) Revoke(context.Context, string, time.Duration) error {
	return errBackendDown
}

// A refused refresh whose session cannot be ended must not answer as a clean refusal: the session stays
// usable, so the request fails with 500 and the outcome is an error.
func TestGuardRefreshRefusalThatCannotEndTheSessionIs500(t *testing.T) {
	refresher := &fakeRefresher{name: "password", refresh: func(*auth.Identity) (*auth.Identity, error) {
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "user deleted"}
	}}
	fixture := newGuardFixture(t, GuardOptions{LoginURL: "/login", Refreshers: []Refresher{refresher}})
	apiRequest := login(t, fixture.store, testIdentity())
	uiRequest := login(t, fixture.store, testIdentity())
	fixture.store.options.Backend = revokeFailingBackend{Backend: fixture.store.options.Backend}
	fixture.clock.advance(2 * time.Minute)

	api := serveGuarded(fixture.guard.RequireAPI(), apiRequest)
	ui := serveGuarded(fixture.guard.RequireUI(), uiRequest)

	for _, result := range []guardResult{api, ui} {
		require.Equal(t, http.StatusInternalServerError, result.recorder.Code)
		require.JSONEq(t, `{"code":"internal","message":"internal error"}`, result.recorder.Body.String(), "no redirect, no refusal body")
		require.Nil(t, result.identity)
	}
	outcomes := fixture.observer.take()
	require.Len(t, outcomes, 2)
	for _, outcome := range outcomes {
		require.Equal(t, auth.ActionRefresh, outcome.Action)
		require.Equal(t, auth.ResultError, outcome.Result)
		require.ErrorIs(t, outcome.Err, errBackendDown)
		require.NotErrorIs(t, outcome.Err, auth.ErrUnauthenticated)
		require.ErrorContains(t, outcome.Err, "user deleted", "the refusal stays readable")
	}

	fixture.clock.advance(time.Second)
	again := serveGuarded(fixture.guard.RequireAPI(), apiRequest)

	require.Equal(t, http.StatusInternalServerError, again.recorder.Code, "the refused identity does not pass on the claim")
	require.Nil(t, again.identity)
	require.Equal(t, 3, refresher.callCount(), "the claim was released, so the next request refreshes again")
}

func TestGuardRefreshFailureKeepsTheIdentity(t *testing.T) {
	testCases := []struct {
		name      string
		refresh   func(*auth.Identity) (*auth.Identity, error)
		wantError string
	}{
		{name: "provider outage", refresh: func(*auth.Identity) (*auth.Identity, error) {
			return nil, errors.New("github unreachable")
		}, wantError: "github unreachable"},
		{name: "no identity returned", refresh: func(*auth.Identity) (*auth.Identity, error) {
			return nil, nil
		}, wantError: `refresher "password" returned no identity`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			refresher := &fakeRefresher{name: "password", refresh: testCase.refresh}
			fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
			request := login(t, fixture.store, testIdentity())
			fixture.clock.advance(2 * time.Minute)

			result := serveGuarded(fixture.guard.RequireAPI(), request)

			require.Equal(t, http.StatusNoContent, result.recorder.Code)
			require.Equal(t, testIdentity(), result.identity)
			outcomes := fixture.observer.take()
			require.Len(t, outcomes, 2)
			require.Equal(t, auth.ActionRefresh, outcomes[0].Action)
			require.Equal(t, auth.ResultSuccess, outcomes[0].Result, "degraded success: nothing answered 500")
			require.ErrorContains(t, outcomes[0].Err, testCase.wantError)
			require.Equal(t, testIdentity(), outcomes[0].Identity)
			require.Equal(t, auth.ResultSuccess, outcomes[1].Result)

			serveGuarded(fixture.guard.RequireAPI(), request)
			require.Equal(t, 1, refresher.callCount(), "one call per interval during an outage")
		})
	}
}

func TestGuardRefreshDoesNotExtendTheAbsoluteLifetime(t *testing.T) {
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		return identity, nil
	}}
	fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request := login(t, fixture.store, testIdentity())

	fixture.clock.advance(24*time.Hour - 30*time.Second)
	require.Equal(t, http.StatusNoContent, serveGuarded(fixture.guard.RequireAPI(), request).recorder.Code)
	require.Equal(t, 1, refresher.callCount())

	fixture.clock.advance(time.Minute)
	require.Equal(t, http.StatusUnauthorized, serveGuarded(fixture.guard.RequireAPI(), request).recorder.Code)
}

func TestGuardRefreshRacingALogout(t *testing.T) {
	var fixture *guardFixture
	var request *http.Request
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		if err := fixture.store.End(t.Context(), httptest.NewRecorder(), request); err != nil {
			return nil, err
		}
		return identity, nil
	}}
	fixture = newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request = login(t, fixture.store, testIdentity())
	fixture.clock.advance(2 * time.Minute)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, http.StatusUnauthorized, result.recorder.Code)
	outcomes := fixture.observer.take()
	require.Len(t, outcomes, 1)
	require.Equal(t, auth.ActionRefresh, outcomes[0].Action)
	require.Equal(t, auth.ResultDenied, outcomes[0].Result)
	require.ErrorIs(t, outcomes[0].Err, auth.ErrUnauthenticated)
	require.ErrorContains(t, outcomes[0].Err, "no session identity")
}

// Requests arriving while a due refresh runs find it claimed: one Refresher call per interval, every
// request answered.
func TestGuardClaimsADueRefresh(t *testing.T) {
	var fixture *guardFixture
	var request *http.Request
	var concurrent []guardResult
	refresher := &fakeRefresher{name: "password"}
	refresher.refresh = func(identity *auth.Identity) (*auth.Identity, error) {
		if concurrent == nil {
			concurrent = []guardResult{}
			for range 15 {
				concurrent = append(concurrent, serveGuarded(fixture.guard.RequireAPI(), request))
			}
		}
		return identity, nil
	}
	fixture = newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request = login(t, fixture.store, testIdentity())
	fixture.clock.advance(2 * time.Minute)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, 1, refresher.callCount())
	for _, answered := range append(concurrent, result) {
		require.Equal(t, http.StatusNoContent, answered.recorder.Code)
		require.Equal(t, testIdentity(), answered.identity)
	}
}

// A request that read a due session and loses the claim to a save made meanwhile does not refresh: the save
// moved refreshedAt. It continues with the identity it read.
func TestGuardLosingTheRefreshClaimSkipsTheRefresh(t *testing.T) {
	saved := testIdentity()
	saved.Roles = []string{"guest"}
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		return identity, nil
	}}
	fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request := login(t, fixture.store, testIdentity())
	fixture.store.options.Backend = &beforeSwapBackend{Backend: fixture.store.options.Backend, beforeSwap: func() {
		concurrent, err := fixture.store.Open(request)
		require.NoError(t, err)
		require.NoError(t, concurrent.SaveIdentity(t.Context(), saved))
	}}
	fixture.clock.advance(2 * time.Minute)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, http.StatusNoContent, result.recorder.Code)
	require.Equal(t, testIdentity(), result.identity)
	require.Zero(t, refresher.callCount())
	current, err := fixture.store.Open(request)
	require.NoError(t, err)
	stored, err := current.Identity(t.Context())
	require.NoError(t, err)
	require.Equal(t, saved, stored)
}

// beforeSwapBackend runs beforeSwap once, before the first CompareAndSwap reaches the backend.
type beforeSwapBackend struct {
	Backend
	beforeSwap func()
}

func (b *beforeSwapBackend) CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	if b.beforeSwap != nil {
		beforeSwap := b.beforeSwap
		b.beforeSwap = nil
		beforeSwap()
	}
	return b.Backend.CompareAndSwap(ctx, sessionID, key, previous, value)
}

// A save completed while a refresh runs (another request's refresh, impersonation, a role change) wins: the
// refresh must not write its older snapshot back, neither after a success nor after a degraded failure.
func TestGuardRefreshLosesToAConcurrentSave(t *testing.T) {
	testCases := []struct {
		name    string
		refresh func(identity *auth.Identity) (*auth.Identity, error)
	}{
		{name: "degraded refresh", refresh: func(*auth.Identity) (*auth.Identity, error) {
			return nil, errors.New("provider unreachable")
		}},
		{name: "successful refresh", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
			return identity, nil
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			saved := testIdentity()
			saved.Roles = []string{"guest"}
			var fixture *guardFixture
			var request *http.Request
			refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
				concurrent, err := fixture.store.Open(request)
				require.NoError(t, err)
				require.NoError(t, concurrent.SaveIdentity(t.Context(), saved))
				return testCase.refresh(identity)
			}}
			fixture = newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
			request = login(t, fixture.store, testIdentity())
			fixture.clock.advance(2 * time.Minute)

			result := serveGuarded(fixture.guard.RequireAPI(), request)

			require.Equal(t, http.StatusNoContent, result.recorder.Code)
			require.Equal(t, saved, result.identity, "the request runs as the concurrent save left the session")
			current, err := fixture.store.Open(request)
			require.NoError(t, err)
			stored, err := current.Identity(t.Context())
			require.NoError(t, err)
			require.Equal(t, saved, stored, "the refresh did not write its snapshot back")
		})
	}
}

// swapFailingBackend passes the first passes CompareAndSwaps on and fails every later one without
// committing it; everything else passes through.
type swapFailingBackend struct {
	Backend
	passes atomic.Int32
}

func (b *swapFailingBackend) CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	if b.passes.Add(-1) >= 0 {
		return b.Backend.CompareAndSwap(ctx, sessionID, key, previous, value)
	}
	return false, errBackendDown
}

func TestGuardAnswersAFailedRefreshSaveWith500(t *testing.T) {
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		return identity, nil
	}}
	fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	backend := &swapFailingBackend{Backend: fixture.store.options.Backend}
	backend.passes.Store(1) // the claim
	fixture.store.options.Backend = backend
	request := login(t, fixture.store, testIdentity())
	fixture.clock.advance(2 * time.Minute)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, http.StatusInternalServerError, result.recorder.Code)
	require.Equal(t, 1, refresher.callCount())
	outcomes := fixture.observer.take()
	require.Len(t, outcomes, 1)
	require.Equal(t, auth.ActionRefresh, outcomes[0].Action)
	require.Equal(t, auth.ResultError, outcomes[0].Result)
	require.ErrorIs(t, outcomes[0].Err, errBackendDown)
}

func TestGuardCallsNoProviderWhileTheBackendFailsWrites(t *testing.T) {
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		return identity, nil
	}}
	fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	fixture.store.options.Backend = &swapFailingBackend{Backend: fixture.store.options.Backend}
	request := login(t, fixture.store, testIdentity())
	fixture.clock.advance(2 * time.Minute)

	for range 30 {
		require.Equal(t, http.StatusInternalServerError, serveGuarded(fixture.guard.RequireAPI(), request).recorder.Code)
	}

	require.Zero(t, refresher.callCount(), "no claim committed, so no request may call the provider")
	outcomes := fixture.observer.take()
	require.Len(t, outcomes, 30)
	require.Equal(t, auth.ResultError, outcomes[0].Result)
	require.ErrorIs(t, outcomes[0].Err, errBackendDown)
}

func TestGuardRefreshRacingTheAbsoluteExpiry(t *testing.T) {
	var fixture *guardFixture
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		fixture.clock.advance(time.Minute)
		return identity, nil
	}}
	fixture = newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request := login(t, fixture.store, testIdentity())
	fixture.clock.advance(24*time.Hour - 30*time.Second)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, http.StatusUnauthorized, result.recorder.Code, "a refresh finishing after the expiry gets no fresh lifetime")
	current, err := fixture.store.Open(request)
	require.NoError(t, err)
	_, err = current.Identity(t.Context())
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
}

// cancellingRefresher cancels the request it refreshes for, as a client hanging up mid-refresh does, then
// answers like a Refresher whose calls honour its context.
type cancellingRefresher struct {
	cancelRequest context.CancelFunc
	answer        func(identity *auth.Identity) (*auth.Identity, error)
}

func (*cancellingRefresher) Name() string {
	return "password"
}

func (r *cancellingRefresher) Refresh(ctx context.Context, _ Session, identity *auth.Identity) (*auth.Identity, error) {
	r.cancelRequest()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.answer(identity)
}

// contextBackend fails every call on an ended context, as the Redis backend does.
type contextBackend struct {
	Backend
}

func (b contextBackend) Get(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return b.Backend.Get(ctx, sessionID, key)
}

func (b contextBackend) CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return b.Backend.CompareAndSwap(ctx, sessionID, key, previous, value)
}

func (b contextBackend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return b.Backend.Revoke(ctx, sessionID, ttl)
}

func TestGuardFinishesARefreshItsClientCancelled(t *testing.T) {
	renamed := testIdentity()
	renamed.Username = "ada-renamed"
	testCases := []struct {
		name         string
		answer       func(identity *auth.Identity) (*auth.Identity, error)
		wantStatus   int
		wantIdentity *auth.Identity // stored afterwards; nil: the session ended
	}{
		{
			name: "a refusal ends the session",
			answer: func(*auth.Identity) (*auth.Identity, error) {
				return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "user deleted"}
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "a refreshed identity is saved",
			answer: func(identity *auth.Identity) (*auth.Identity, error) {
				refreshed := identity.Clone()
				refreshed.Username = "ada-renamed"
				return refreshed, nil
			},
			wantStatus: http.StatusNoContent, wantIdentity: renamed,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			refresher := &cancellingRefresher{answer: testCase.answer}
			fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
			fixture.store.options.Backend = contextBackend{Backend: fixture.store.options.Backend}
			request := login(t, fixture.store, testIdentity())
			ctx, cancel := context.WithCancel(t.Context())
			refresher.cancelRequest = cancel
			fixture.clock.advance(2 * time.Minute)

			result := serveGuarded(fixture.guard.RequireAPI(), request.WithContext(ctx))

			require.Equal(t, testCase.wantStatus, result.recorder.Code)
			current, err := fixture.store.Open(request)
			require.NoError(t, err)
			stored, err := current.Identity(t.Context())
			if testCase.wantIdentity == nil {
				require.ErrorIs(t, err, auth.ErrUnauthenticated, "the session ended")
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.wantIdentity, stored)
		})
	}
}

// clearVerifiedAt stores the session's envelope without verifiedAt, as sessions saved before it existed are.
func clearVerifiedAt(t *testing.T, store *Store, request *http.Request) {
	t.Helper()
	current, err := store.Open(request)
	require.NoError(t, err)
	stored, err := current.envelope(t.Context())
	require.NoError(t, err)
	stored.VerifiedAt = time.Time{}
	_, swapped, err := current.swapEnvelope(t.Context(), stored)
	require.NoError(t, err)
	require.True(t, swapped)
}

func TestGuardEndsASessionWhoseRefreshFailsBeyondTheMaximumUnverifiedAge(t *testing.T) {
	errOutage := errors.New("provider down")
	testCases := []struct {
		name            string
		clearVerifiedAt bool
		after           time.Duration
		wantEnded       bool
	}{
		{name: "failing within the bound keeps the identity", after: 30 * time.Minute},
		{name: "failing beyond the bound ends the session", after: 61 * time.Minute, wantEnded: true},
		{name: "a session without verifiedAt counts from its login", clearVerifiedAt: true, after: 30 * time.Minute},
		{name: "a session without verifiedAt ends beyond the bound", clearVerifiedAt: true, after: 61 * time.Minute, wantEnded: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			refresher := &fakeRefresher{name: "password", refresh: func(*auth.Identity) (*auth.Identity, error) {
				return nil, errOutage
			}}
			fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
			request := login(t, fixture.store, testIdentity())
			if testCase.clearVerifiedAt {
				clearVerifiedAt(t, fixture.store, request)
			}
			fixture.clock.advance(testCase.after)

			result := serveGuarded(fixture.guard.RequireAPI(), request)

			refreshOutcome := fixture.observer.take()[0]
			require.Equal(t, auth.ActionRefresh, refreshOutcome.Action)
			require.ErrorIs(t, refreshOutcome.Err, errOutage)
			if !testCase.wantEnded {
				require.Equal(t, http.StatusNoContent, result.recorder.Code)
				require.Equal(t, testIdentity(), result.identity)
				require.Equal(t, auth.ResultSuccess, refreshOutcome.Result, "degraded")
				return
			}
			require.Equal(t, http.StatusUnauthorized, result.recorder.Code)
			requireExpiredCookie(t, result.recorder)
			current, err := fixture.store.Open(request)
			require.NoError(t, err)
			_, err = current.Identity(t.Context())
			require.ErrorIs(t, err, auth.ErrUnauthenticated, "session ended")
			require.Equal(t, auth.ResultDenied, refreshOutcome.Result)
			var refusal *auth.Error
			require.ErrorAs(t, refreshOutcome.Err, &refusal)
			require.Equal(t, "identity could not be verified", refusal.Reason)
		})
	}
}

func TestGuardRestartsTheUnverifiedAgeOnASuccessfulRefresh(t *testing.T) {
	failing := false
	refresher := &fakeRefresher{name: "password", refresh: func(identity *auth.Identity) (*auth.Identity, error) {
		if failing {
			return nil, errors.New("provider down")
		}
		return identity, nil
	}}
	fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
	request := login(t, fixture.store, testIdentity())
	fixture.clock.advance(50 * time.Minute)
	require.Equal(t, http.StatusNoContent, serveGuarded(fixture.guard.RequireAPI(), request).recorder.Code)
	failing = true
	fixture.clock.advance(50 * time.Minute)

	result := serveGuarded(fixture.guard.RequireAPI(), request)

	require.Equal(t, http.StatusNoContent, result.recorder.Code, "verified 50 minutes ago, 100 after the login")
	require.Equal(t, testIdentity(), result.identity)
}

// lostClaimReplyBackend commits the first CompareAndSwap and then reports it failed, as a swap whose reply
// was lost to a dropped connection does; every later call passes through.
type lostClaimReplyBackend struct {
	Backend
	lost atomic.Bool
}

func (b *lostClaimReplyBackend) CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	swapped, err := b.Backend.CompareAndSwap(ctx, sessionID, key, previous, value)
	if err == nil && b.lost.CompareAndSwap(false, true) {
		return false, context.Canceled
	}
	return swapped, err
}

func TestGuardRefreshesWhenTheClaimsReplyIsLost(t *testing.T) {
	testCases := []struct {
		name   string
		answer error
		after  time.Duration
	}{
		{name: "a refusal still ends the session", answer: &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "user deleted"}, after: 2 * time.Minute},
		{name: "a failure beyond the maximum unverified age still ends it", answer: errors.New("provider down"), after: 61 * time.Minute},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			refresher := &fakeRefresher{name: "password", refresh: func(*auth.Identity) (*auth.Identity, error) {
				return nil, testCase.answer
			}}
			fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
			request := login(t, fixture.store, testIdentity())
			fixture.store.options.Backend = &lostClaimReplyBackend{Backend: fixture.store.options.Backend}
			fixture.clock.advance(testCase.after)

			first := serveGuarded(fixture.guard.RequireAPI(), request)
			next := serveGuarded(fixture.guard.RequireAPI(), request)

			require.Equal(t, 1, refresher.callCount(), "the claim committed, so the refresh ran")
			require.Equal(t, http.StatusUnauthorized, first.recorder.Code)
			require.Equal(t, http.StatusUnauthorized, next.recorder.Code, "the session did not pass as fresh")
			require.Nil(t, next.identity)
		})
	}
}

func TestGuardRefreshIsDueDespiteApplicationSaves(t *testing.T) {
	testCases := []struct {
		name string
		save func(t *testing.T, current Session)
	}{
		{name: "SaveIdentity", save: func(t *testing.T, current Session) {
			require.NoError(t, current.SaveIdentity(t.Context(), testIdentity()))
		}},
		{name: "SwapIdentity", save: func(t *testing.T, current Session) {
			swapped, err := current.SwapIdentity(t.Context(), testIdentity(), testIdentity())
			require.NoError(t, err)
			require.True(t, swapped)
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			refresher := &fakeRefresher{name: "password", refresh: func(*auth.Identity) (*auth.Identity, error) {
				return nil, &auth.Error{Kind: auth.ErrForbidden, Reason: "removed from the team"}
			}}
			fixture := newGuardFixture(t, GuardOptions{Refreshers: []Refresher{refresher}})
			request := login(t, fixture.store, testIdentity())
			current, err := fixture.store.Open(request)
			require.NoError(t, err)
			fixture.clock.advance(50 * time.Second)
			testCase.save(t, current) // more often than RefreshInterval
			require.Equal(t, http.StatusNoContent, serveGuarded(fixture.guard.RequireAPI(), request).recorder.Code)
			fixture.clock.advance(50 * time.Second)
			testCase.save(t, current)

			result := serveGuarded(fixture.guard.RequireAPI(), request)

			require.Equal(t, 1, refresher.callCount(), "due 100 s after the login, saves or not")
			require.Equal(t, http.StatusForbidden, result.recorder.Code)
		})
	}
}
