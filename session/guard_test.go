package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
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
		name    string
		options *GuardOptions
		wantErr string
	}{
		{name: "nil options", wantErr: "Store is required"},
		{name: "no store", options: &GuardOptions{}, wantErr: "Store is required"},
		{name: "relative login URL", options: &GuardOptions{Store: store, LoginURL: "login"}, wantErr: "LoginURL must be"},
		{name: "protocol relative login URL", options: &GuardOptions{Store: store, LoginURL: "//evil.example/login"}, wantErr: "LoginURL must be"},
		{name: "backslash login URL", options: &GuardOptions{Store: store, LoginURL: "/\\evil.example"}, wantErr: "LoginURL must be"},
		{name: "other scheme", options: &GuardOptions{Store: store, LoginURL: "ftp://example.com/login"}, wantErr: "LoginURL must be"},
		{name: "absolute URL without host", options: &GuardOptions{Store: store, LoginURL: "https:///login"}, wantErr: "LoginURL must be"},
		{name: "negative refresh interval", options: &GuardOptions{Store: store, RefreshInterval: -time.Second}, wantErr: "RefreshInterval -1s is negative"},
		{name: "nil refresher", options: &GuardOptions{Store: store, Refreshers: []Refresher{nil}}, wantErr: "every Refresher needs a name"},
		{name: "unnamed refresher", options: &GuardOptions{Store: store, Refreshers: []Refresher{&fakeRefresher{}}}, wantErr: "every Refresher needs a name"},
		{name: "duplicate refresher names", options: &GuardOptions{Store: store, Refreshers: []Refresher{refresher, &fakeRefresher{name: "password"}}}, wantErr: `two Refreshers are named "password"`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			guard, err := NewGuard(testCase.options)
			require.ErrorContains(t, err, testCase.wantErr)
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
	require.Equal(t, map[string]Refresher{"password": refresher}, guard.refreshers)

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
			request.AddCookie(&http.Cookie{Name: "auth_session", Value: "forged"})
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
		name       string
		refusal    error
		wantAPI    int
		wantUI     int
		wantAPIErr string
	}{
		{name: "unauthenticated", refusal: &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "user deleted"}, wantAPI: http.StatusUnauthorized, wantUI: http.StatusFound, wantAPIErr: `{"code":"unauthenticated","message":"authentication required"}`},
		{name: "forbidden", refusal: &auth.Error{Kind: auth.ErrForbidden, Reason: "not in an allowed team"}, wantAPI: http.StatusForbidden, wantUI: http.StatusForbidden, wantAPIErr: `{"code":"forbidden","message":"access denied"}`},
		{name: "bare sentinel", refusal: auth.ErrForbidden, wantAPI: http.StatusForbidden, wantUI: http.StatusForbidden, wantAPIErr: `{"code":"forbidden","message":"access denied"}`},
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
			require.JSONEq(t, testCase.wantAPIErr, api.recorder.Body.String())
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

func TestGuardRefreshFailureKeepsTheIdentity(t *testing.T) {
	testCases := []struct {
		name    string
		refresh func(*auth.Identity) (*auth.Identity, error)
		wantErr string
	}{
		{name: "provider outage", refresh: func(*auth.Identity) (*auth.Identity, error) {
			return nil, errors.New("github unreachable")
		}, wantErr: "github unreachable"},
		{name: "no identity returned", refresh: func(*auth.Identity) (*auth.Identity, error) {
			return nil, nil
		}, wantErr: `refresher "password" returned no identity`},
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
			require.ErrorContains(t, outcomes[0].Err, testCase.wantErr)
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
	require.ErrorIs(t, outcomes[0].Err, ErrSessionRevoked)
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
