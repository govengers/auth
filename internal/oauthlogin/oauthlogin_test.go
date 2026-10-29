package oauthlogin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

const loginKey = "oidc.login"

var errBackendDown = errors.New("backend down")

// recordingBackend records the TTLs of Puts and can fail Pops.
type recordingBackend struct {
	session.Backend
	mutex    sync.Mutex
	ttls     map[string]time.Duration
	popError error
}

func (b *recordingBackend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	b.mutex.Lock()
	b.ttls[key] = ttl
	b.mutex.Unlock()
	return b.Backend.Put(ctx, sessionID, key, value, ttl)
}

func (b *recordingBackend) Pop(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if b.popError != nil {
		return nil, false, b.popError
	}
	return b.Backend.Pop(ctx, sessionID, key)
}

func newRecordingStore(t *testing.T) (*session.Store, *recordingBackend) {
	t.Helper()
	memory, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	backend := &recordingBackend{Backend: memory, ttls: map[string]time.Duration{}}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	return store, backend
}

// begin runs Begin for target and returns the state and a callback request builder carrying the session cookie.
func begin(t *testing.T, store *session.Store, target string) (State, func(query url.Values) *http.Request) {
	t.Helper()
	recorder := httptest.NewRecorder()
	state, err := Begin(t.Context(), store, recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil), loginKey)
	require.NoError(t, err)
	cookies := recorder.Header().Values("Set-Cookie")
	require.Len(t, cookies, 1)
	cookie, err := http.ParseSetCookie(cookies[0])
	require.NoError(t, err)
	return state, func(query url.Values) *http.Request {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback?"+query.Encode(), nil)
		request.AddCookie(cookie)
		return request
	}
}

func TestBegin(t *testing.T) {
	testCases := []struct {
		name           string
		target         string
		wantReturnPath string
	}{
		{name: "safe return path", target: "/login?return_to=%2Fdashboard%3Ftab%3D2", wantReturnPath: "/dashboard?tab=2"},
		{name: "no return path", target: "/login", wantReturnPath: "/"},
		{name: "unsafe return path", target: "/login?return_to=%2F%2Fevil.example", wantReturnPath: "/"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store, backend := newRecordingStore(t)

			state, callback := begin(t, store, testCase.target)

			require.Equal(t, testCase.wantReturnPath, state.ReturnPath)
			for _, token := range []string{state.State, state.Nonce, state.Verifier} {
				require.Len(t, token, 43, "32 random bytes, base64url")
			}
			require.NotEqual(t, state.State, state.Nonce)
			require.NotEqual(t, state.State, state.Verifier)
			require.Equal(t, 10*time.Minute, backend.ttls[loginKey])
			completed, err := Complete(t.Context(), store, callback(url.Values{"state": {state.State}, "code": {"code"}}), loginKey)
			require.NoError(t, err)
			require.Equal(t, state, completed)
		})
	}
}

func TestBeginFailsWhenTheStateCannotBeStored(t *testing.T) {
	store, err := session.NewStore(&session.StoreOptions{Backend: failingBackend{}, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)

	_, err = Begin(t.Context(), store, httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil), loginKey)

	require.ErrorIs(t, err, errBackendDown)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil)
	request.AddCookie(&http.Cookie{Name: "auth_session", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	_, err = Begin(t.Context(), store, httptest.NewRecorder(), request, loginKey)
	require.ErrorIs(t, err, errBackendDown, "the previous session cannot be revoked")
}

func TestComplete(t *testing.T) {
	testCases := []struct {
		name       string
		query      func(state State) url.Values
		otherKey   bool
		noCookie   bool
		wantStatus int
		wantCode   string
	}{
		{name: "success", query: func(state State) url.Values { return url.Values{"state": {state.State}, "code": {"code"}} }},
		{name: "provider error", query: func(state State) url.Values {
			return url.Values{"state": {state.State}, "error": {"access_denied"}}
		}, wantStatus: http.StatusUnauthorized, wantCode: "login_denied"},
		{name: "no session cookie", query: func(state State) url.Values {
			return url.Values{"state": {state.State}, "code": {"code"}}
		}, noCookie: true, wantStatus: http.StatusBadRequest, wantCode: "login_expired"},
		{name: "state of another provider", query: func(state State) url.Values {
			return url.Values{"state": {state.State}, "code": {"code"}}
		}, otherKey: true, wantStatus: http.StatusBadRequest, wantCode: "login_expired"},
		{name: "state mismatch", query: func(State) url.Values {
			return url.Values{"state": {"forged"}, "code": {"code"}}
		}, wantStatus: http.StatusBadRequest, wantCode: "state_mismatch"},
		{name: "no state", query: func(State) url.Values { return url.Values{"code": {"code"}} }, wantStatus: http.StatusBadRequest, wantCode: "state_mismatch"},
		{name: "no code", query: func(state State) url.Values { return url.Values{"state": {state.State}} }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store, _ := newRecordingStore(t)
			state, callback := begin(t, store, "/login")
			request := callback(testCase.query(state))
			if testCase.noCookie {
				request.Header.Del("Cookie")
			}
			key := loginKey
			if testCase.otherKey {
				key = "github.login"
			}

			completed, err := Complete(t.Context(), store, request, key)

			if testCase.wantCode == "" {
				require.NoError(t, err)
				require.Equal(t, state, completed)
				return
			}
			var refusal *auth.Error
			require.ErrorAs(t, err, &refusal)
			status, response := auth.ResponseFor(err)
			require.Equal(t, testCase.wantStatus, status)
			require.Equal(t, testCase.wantCode, response.Code)
			require.Equal(t, State{}, completed)
		})
	}
}

func TestCompleteIsSingleUse(t *testing.T) {
	store, _ := newRecordingStore(t)
	state, callback := begin(t, store, "/login")
	valid := url.Values{"state": {state.State}, "code": {"code"}}

	_, err := Complete(t.Context(), store, callback(valid), loginKey)
	require.NoError(t, err)

	_, err = Complete(t.Context(), store, callback(valid), loginKey)
	requireCode(t, err, "login_expired")
}

func TestCompleteConsumesTheStateOnAMismatch(t *testing.T) {
	store, _ := newRecordingStore(t)
	state, callback := begin(t, store, "/login")

	_, err := Complete(t.Context(), store, callback(url.Values{"state": {"forged"}, "code": {"code"}}), loginKey)
	requireCode(t, err, "state_mismatch")

	_, err = Complete(t.Context(), store, callback(url.Values{"state": {state.State}, "code": {"code"}}), loginKey)
	requireCode(t, err, "login_expired")
}

func TestCompleteKeepsTheStateOnAProviderError(t *testing.T) {
	store, _ := newRecordingStore(t)
	state, callback := begin(t, store, "/login")

	_, err := Complete(t.Context(), store, callback(url.Values{"error": {"access_denied"}}), loginKey)
	requireCode(t, err, "login_denied")

	_, err = Complete(t.Context(), store, callback(url.Values{"state": {state.State}, "code": {"code"}}), loginKey)
	require.NoError(t, err)
}

func TestCompleteRefusesAnUnreadableState(t *testing.T) {
	store, _ := newRecordingStore(t)
	_, callback := begin(t, store, "/login")
	request := callback(url.Values{"state": {""}, "code": {"code"}})
	current, err := store.Open(request)
	require.NoError(t, err)
	for _, stored := range []string{"not json", `{"state":""}`} {
		require.NoError(t, current.Put(t.Context(), loginKey, []byte(stored), time.Minute))

		_, err = Complete(t.Context(), store, request, loginKey)

		requireCode(t, err, "login_expired")
	}
}

func TestCompleteReportsABackendFailure(t *testing.T) {
	store, backend := newRecordingStore(t)
	state, callback := begin(t, store, "/login")
	backend.popError = errBackendDown

	_, err := Complete(t.Context(), store, callback(url.Values{"state": {state.State}, "code": {"code"}}), loginKey)

	require.ErrorIs(t, err, errBackendDown)
	status, _ := auth.ResponseFor(err)
	require.Equal(t, http.StatusInternalServerError, status)
}

func requireCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	_, response := auth.ResponseFor(err)
	require.Equal(t, wantCode, response.Code)
}

type failingBackend struct{}

func (failingBackend) Put(context.Context, string, string, []byte, time.Duration) error {
	return errBackendDown
}

func (failingBackend) Get(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, errBackendDown
}

func (failingBackend) Pop(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, errBackendDown
}

func (failingBackend) Revoke(context.Context, string, time.Duration) error {
	return errBackendDown
}
