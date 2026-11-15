package devlogin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

var (
	testEncryptionKey = []byte("0123456789abcdef0123456789abcdef")
	adaID             = uuid.MustParse("6f1c2a4e-8d3b-4f5a-9c7e-1b2d3e4f5a6b")
)

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

// last returns the only outcome recorded since the last call.
func (r *outcomeRecorder) last(t *testing.T) auth.Outcome {
	t.Helper()
	r.mutex.Lock()
	defer r.mutex.Unlock()
	require.Len(t, r.outcomes, 1)
	outcome := r.outcomes[0]
	r.outcomes = nil
	return outcome
}

type fixture struct {
	outcomes *outcomeRecorder
	handler  http.Handler
}

// loadTestUser stands in for the application's user table: ada is an active admin, bob inactive, fail fails to load and
// forbidden is refused by the application.
func loadTestUser(_ context.Context, id string) (*auth.Identity, error) {
	switch id {
	case "ada":
		return &auth.Identity{Provider: "password", Subject: "overwritten", UserID: adaID, Username: "ada", Roles: []string{auth.RoleAdmin}, Active: true}, nil
	case "bob":
		return &auth.Identity{Username: "bob"}, nil
	case "fail":
		return nil, errors.New("database down")
	case "forbidden":
		return nil, &auth.Error{Kind: auth.ErrForbidden, Reason: "other tenant"}
	}
	return nil, nil
}

func newFixture(t *testing.T, change func(options *Options)) *fixture {
	t.Helper()
	backend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	sessions, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: testEncryptionKey, InsecureCookie: true})
	require.NoError(t, err)
	guard, err := session.NewGuard(&session.GuardOptions{Store: sessions})
	require.NoError(t, err)
	outcomes := &outcomeRecorder{}
	options := &Options{
		Enabled:  true,
		Sessions: sessions,
		Users: func(context.Context) ([]User, error) {
			return []User{{ID: "ada", Name: "Ada", Description: "admin"}, {ID: "bob", Name: "Bob"}}, nil
		},
		Load:     loadTestUser,
		Observer: outcomes.observe,
	}
	if change != nil {
		change(options)
	}
	provider, err := New(options)
	require.NoError(t, err)
	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes())
	serveMux.Handle("GET /api/me", guard.RequireAPI()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.NoError(t, json.NewEncoder(writer).Encode(auth.IdentityFrom(request.Context())))
	})))
	return &fixture{outcomes: outcomes, handler: serveMux}
}

// localRequest is a request straight from a browser on this machine.
func localRequest(method, target, body string) *http.Request {
	request := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:52100"
	request.Host = "localhost:8080"
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

// send serves request with the cookies an earlier response set, as a browser would.
func (f *fixture) send(request *http.Request, earlier *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	if earlier != nil {
		for _, line := range earlier.Header().Values("Set-Cookie") {
			if cookie, err := http.ParseSetCookie(line); err == nil {
				request.AddCookie(cookie)
			}
		}
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder
}

func errorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body auth.ErrorResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	return body.Code
}

func TestNewRefusesWithoutEnabled(t *testing.T) {
	store := &session.Store{}
	users := func(context.Context) ([]User, error) { return nil, nil }
	testCases := []struct {
		name      string
		options   *Options
		wantError string
	}{
		{name: "nil options", options: nil, wantError: "Enabled is false"},
		{name: "not enabled", options: &Options{Sessions: store, Users: users, Load: loadTestUser}, wantError: "Enabled is false"},
		{name: "no sessions", options: &Options{Enabled: true, Users: users, Load: loadTestUser}, wantError: "need Sessions, Users and Load"},
		{name: "no users", options: &Options{Enabled: true, Sessions: store, Load: loadTestUser}, wantError: "need Sessions, Users and Load"},
		{name: "no load", options: &Options{Enabled: true, Sessions: store, Users: users}, wantError: "need Sessions, Users and Load"},
		{name: "bad prefix", options: &Options{Enabled: true, Sessions: store, Users: users, Load: loadTestUser, PathPrefix: "/dev/"}, wantError: "PathPrefix"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider, err := New(testCase.options)
			require.ErrorContains(t, err, testCase.wantError)
			require.Nil(t, provider)
		})
	}
}

func TestRoutes(t *testing.T) {
	provider, err := New(&Options{Enabled: true, Sessions: &session.Store{}, Users: func(context.Context) ([]User, error) { return nil, nil }, Load: loadTestUser, PathPrefix: "/local"})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderDev, provider.Name())
	var patterns []string
	for _, route := range provider.Routes() {
		patterns = append(patterns, route.Method+" "+route.Path)
	}
	require.Equal(t, []string{"GET /local/users", "POST /local/login", "POST /local/logout"}, patterns)
}

func TestUsers(t *testing.T) {
	devFixture := newFixture(t, nil)
	recorder := devFixture.send(localRequest(http.MethodGet, "/auth/dev/users", ""), nil)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.JSONEq(t, `{"users":[{"id":"ada","name":"Ada","description":"admin"},{"id":"bob","name":"Bob"}]}`, recorder.Body.String())
	outcome := devFixture.outcomes.last(t)
	require.Equal(t, auth.Outcome{Provider: auth.ProviderDev, Action: auth.ActionListUsers, Result: auth.ResultSuccess}, outcome)

	empty := newFixture(t, func(options *Options) {
		options.Users = func(context.Context) ([]User, error) { return nil, nil }
	})
	recorder = empty.send(localRequest(http.MethodGet, "/auth/dev/users", ""), nil)
	require.JSONEq(t, `{"users":[]}`, recorder.Body.String())

	failing := newFixture(t, func(options *Options) {
		options.Users = func(context.Context) ([]User, error) { return nil, errors.New("database down") }
	})
	recorder = failing.send(localRequest(http.MethodGet, "/auth/dev/users", ""), nil)
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	outcome = failing.outcomes.last(t)
	require.Equal(t, auth.ResultError, outcome.Result)
	require.ErrorContains(t, outcome.Err, "list dev users: database down")
}

func TestLoginStartsANormalSession(t *testing.T) {
	devFixture := newFixture(t, nil)
	login := devFixture.send(localRequest(http.MethodPost, "/auth/dev/login", `{"id":"ada"}`), nil)
	require.Equal(t, http.StatusOK, login.Code)
	var response auth.IdentityResponse
	require.NoError(t, json.Unmarshal(login.Body.Bytes(), &response))
	require.Equal(t, auth.ProviderDev, response.Provider)
	require.Equal(t, "ada", response.Subject)
	require.Equal(t, []string{auth.RoleAdmin}, response.Roles)
	outcome := devFixture.outcomes.last(t)
	require.Equal(t, auth.ActionLogin, outcome.Action)
	require.Equal(t, auth.ResultSuccess, outcome.Result)
	require.Equal(t, auth.ProviderDev, outcome.Provider)
	require.Equal(t, adaID, outcome.Identity.UserID)

	current := devFixture.send(localRequest(http.MethodGet, "/api/me", ""), login)
	require.Equal(t, http.StatusOK, current.Code)
	var identity auth.Identity
	require.NoError(t, json.Unmarshal(current.Body.Bytes(), &identity))
	require.Equal(t, auth.Identity{Provider: auth.ProviderDev, Subject: "ada", UserID: adaID, Username: "ada", Roles: []string{auth.RoleAdmin}, Active: true}, identity)

	logout := devFixture.send(localRequest(http.MethodPost, "/auth/dev/logout", ""), login)
	require.Equal(t, http.StatusNoContent, logout.Code)
	outcome = devFixture.outcomes.last(t)
	require.Equal(t, auth.Outcome{Provider: auth.ProviderDev, Action: auth.ActionLogout, Result: auth.ResultSuccess, Identity: &identity}, outcome)
	require.Equal(t, http.StatusUnauthorized, devFixture.send(localRequest(http.MethodGet, "/api/me", ""), login).Code)
}

func TestLoginRefusals(t *testing.T) {
	testCases := []struct {
		name       string
		body       string
		header     map[string]string
		wantStatus int
		wantCode   string
		wantResult auth.Result
	}{
		{name: "unknown user", body: `{"id":"carol"}`, wantStatus: http.StatusBadRequest, wantCode: codeUnknownUser, wantResult: auth.ResultDenied},
		{name: "empty ID", body: `{"id":""}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantResult: auth.ResultDenied},
		{name: "unknown field", body: `{"user":"ada"}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantResult: auth.ResultDenied},
		{name: "form post", body: `id=ada`, header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request", wantResult: auth.ResultDenied},
		{name: "inactive user", body: `{"id":"bob"}`, wantStatus: http.StatusForbidden, wantCode: "forbidden", wantResult: auth.ResultDenied},
		{name: "refused by Load", body: `{"id":"forbidden"}`, wantStatus: http.StatusForbidden, wantCode: "forbidden", wantResult: auth.ResultDenied},
		{name: "Load fails", body: `{"id":"fail"}`, wantStatus: http.StatusInternalServerError, wantCode: "internal", wantResult: auth.ResultError},
		{name: "cross-site", body: `{"id":"ada"}`, header: map[string]string{"Sec-Fetch-Site": "cross-site"}, wantStatus: http.StatusForbidden, wantCode: "forbidden", wantResult: auth.ResultDenied},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			devFixture := newFixture(t, nil)
			request := localRequest(http.MethodPost, "/auth/dev/login", testCase.body)
			for name, value := range testCase.header {
				request.Header.Set(name, value)
			}
			recorder := devFixture.send(request, nil)
			require.Equal(t, testCase.wantStatus, recorder.Code)
			require.Equal(t, testCase.wantCode, errorCode(t, recorder))
			require.Empty(t, recorder.Header().Values("Set-Cookie"), "no session")
			outcome := devFixture.outcomes.last(t)
			require.Equal(t, auth.ActionLogin, outcome.Action)
			require.Equal(t, testCase.wantResult, outcome.Result)
		})
	}
}

func TestLogoutRefusesCrossSite(t *testing.T) {
	devFixture := newFixture(t, nil)
	login := devFixture.send(localRequest(http.MethodPost, "/auth/dev/login", `{"id":"ada"}`), nil)
	devFixture.outcomes.last(t)
	request := localRequest(http.MethodPost, "/auth/dev/logout", "")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	require.Equal(t, http.StatusForbidden, devFixture.send(request, login).Code)
	require.Equal(t, auth.ResultDenied, devFixture.outcomes.last(t).Result)
	require.Equal(t, http.StatusOK, devFixture.send(localRequest(http.MethodGet, "/api/me", ""), login).Code)

	// without a session, logout only expires the cookie
	require.Equal(t, http.StatusNoContent, devFixture.send(localRequest(http.MethodPost, "/auth/dev/logout", ""), nil).Code)
	require.Equal(t, auth.Outcome{Provider: auth.ProviderDev, Action: auth.ActionLogout, Result: auth.ResultSuccess}, devFixture.outcomes.last(t))
}

func TestLocalOnly(t *testing.T) {
	testCases := []struct {
		name        string
		remote      string
		host        string
		header      string
		allowRemote bool
		wantLocal   bool
	}{
		{name: "IPv4 loopback, localhost", remote: "127.0.0.1:1", host: "localhost:8080", wantLocal: true},
		{name: "other loopback address", remote: "127.0.0.2:1", host: "127.0.0.1:8080", wantLocal: true},
		{name: "IPv6 loopback", remote: "[::1]:1", host: "[::1]:8080", wantLocal: true},
		{name: "IPv4-mapped loopback", remote: "[::ffff:127.0.0.1]:1", host: "localhost", wantLocal: true},
		{name: "localhost subdomain, upper case, trailing dot", remote: "127.0.0.1:1", host: "App.Localhost.:5173", wantLocal: true},
		{name: "host without port", remote: "127.0.0.1:1", host: "[::1]", wantLocal: true},
		{name: "remote peer", remote: "192.0.2.1:1", host: "localhost:8080"},
		{name: "container network peer", remote: "172.17.0.1:1", host: "localhost:8080"},
		{name: "peer without port", remote: "127.0.0.1", host: "localhost:8080"},
		{name: "DNS rebinding host", remote: "127.0.0.1:1", host: "attacker.example:8080"},
		{name: "localhost lookalike", remote: "127.0.0.1:1", host: "localhost.example"},
		{name: "proxied, X-Forwarded-For", remote: "127.0.0.1:1", host: "localhost", header: "X-Forwarded-For"},
		{name: "proxied, Forwarded", remote: "127.0.0.1:1", host: "localhost", header: "Forwarded"},
		{name: "proxied, X-Real-IP", remote: "127.0.0.1:1", host: "localhost", header: "X-Real-IP"},
		{name: "remote peer allowed", remote: "172.17.0.1:1", host: "app.example", header: "X-Forwarded-For", allowRemote: true, wantLocal: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			devFixture := newFixture(t, func(options *Options) { options.AllowRemote = testCase.allowRemote })
			for _, route := range []struct{ method, path, body string }{
				{http.MethodGet, "/auth/dev/users", ""},
				{http.MethodPost, "/auth/dev/login", `{"id":"ada"}`},
				{http.MethodPost, "/auth/dev/logout", ""},
			} {
				request := localRequest(route.method, route.path, route.body)
				request.RemoteAddr, request.Host = testCase.remote, testCase.host
				if testCase.header != "" {
					request.Header.Set(testCase.header, "192.0.2.1")
				}
				recorder := devFixture.send(request, nil)
				outcome := devFixture.outcomes.last(t)
				if testCase.wantLocal {
					require.Less(t, recorder.Code, 300, route.path)
					continue
				}
				require.Equal(t, http.StatusForbidden, recorder.Code, route.path)
				require.Equal(t, codeNotLocal, errorCode(t, recorder))
				require.Equal(t, auth.ResultDenied, outcome.Result)
				require.Equal(t, auth.ProviderDev, outcome.Provider)
			}
		})
	}
}
