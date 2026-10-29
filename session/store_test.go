package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/random"
)

func TestNewStoreValidation(t *testing.T) {
	backend := newTestMemoryBackend(t, newTestClock())
	valid := func(change func(options *StoreOptions)) *StoreOptions {
		options := &StoreOptions{Backend: backend, EncryptionKey: testEncryptionKey()}
		change(options)
		return options
	}
	testCases := []struct {
		name    string
		options *StoreOptions
		wantErr string
	}{
		{name: "nil options", options: nil, wantErr: "Backend is required"},
		{name: "no backend", options: valid(func(options *StoreOptions) { options.Backend = nil }), wantErr: "Backend is required"},
		{name: "no key", options: valid(func(options *StoreOptions) { options.EncryptionKey = nil }), wantErr: "EncryptionKey has 0 bytes"},
		{name: "short key", options: valid(func(options *StoreOptions) { options.EncryptionKey = options.EncryptionKey[:31] }), wantErr: "EncryptionKey has 31 bytes"},
		{name: "long key", options: valid(func(options *StoreOptions) { options.EncryptionKey = append(options.EncryptionKey, 'x') }), wantErr: "EncryptionKey has 33 bytes"},
		{name: "max age below a second", options: valid(func(options *StoreOptions) { options.MaxAge = 500 * time.Millisecond }), wantErr: "below one second"},
		{name: "negative max age", options: valid(func(options *StoreOptions) { options.MaxAge = -time.Hour }), wantErr: "below one second"},
		{name: "unknown same site", options: valid(func(options *StoreOptions) { options.SameSite = 9 }), wantErr: "SameSite 9 is unknown"},
		{name: "same site none on an insecure cookie", options: valid(func(options *StoreOptions) {
			options.SameSite = http.SameSiteNoneMode
			options.InsecureCookie = true
		}), wantErr: "SameSite None requires a Secure cookie"},
		{name: "relative cookie path", options: valid(func(options *StoreOptions) { options.CookiePath = "app" }), wantErr: "CookiePath must start with"},
		{name: "cookie path with semicolon", options: valid(func(options *StoreOptions) { options.CookiePath = "/a;b" }), wantErr: "in Cookie.Path"},
		{name: "cookie name with space", options: valid(func(options *StoreOptions) { options.CookieName = "bad name" }), wantErr: "invalid Cookie.Name"},
		{name: "invalid cookie domain", options: valid(func(options *StoreOptions) { options.CookieDomain = "bad domain!" }), wantErr: "invalid Cookie.Domain"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store, err := NewStore(testCase.options)
			require.ErrorContains(t, err, testCase.wantErr)
			require.Nil(t, store)
		})
	}
}

func TestNewStoreDefaultsOnACopy(t *testing.T) {
	key := testEncryptionKey()
	options := &StoreOptions{Backend: newTestMemoryBackend(t, newTestClock()), EncryptionKey: key}
	original := *options
	original.EncryptionKey = slices.Clone(key)

	store, err := NewStore(options)

	require.NoError(t, err)
	require.Equal(t, original, *options, "caller's options untouched")
	require.Equal(t, "auth_session", store.options.CookieName)
	require.Equal(t, "/", store.options.CookiePath)
	require.Equal(t, http.SameSiteLaxMode, store.options.SameSite)
	require.Equal(t, 24*time.Hour, store.MaxAge())

	current, request := startSession(t, store)
	require.NoError(t, current.Put(t.Context(), "app.key", []byte("value"), time.Hour))
	key[0] ^= 0xff
	opened, err := store.Open(request)
	require.NoError(t, err)
	value, found, err := opened.Get(t.Context(), "app.key")
	require.NoError(t, err)
	require.True(t, found, "a changed caller key does not change the store's key")
	require.Equal(t, "value", string(value))
}

func TestStartSetsTheCookie(t *testing.T) {
	testCases := []struct {
		name    string
		options StoreOptions
		want    string // Set-Cookie header with the value replaced by <value>
	}{
		{
			name: "defaults",
			want: "auth_session=<value>; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax",
		},
		{
			name:    "configured",
			options: StoreOptions{CookieName: "app", CookieDomain: "example.com", CookiePath: "/app", SameSite: http.SameSiteStrictMode, InsecureCookie: true, MaxAge: time.Hour},
			want:    "app=<value>; Path=/app; Domain=example.com; Max-Age=3600; HttpOnly; SameSite=Strict",
		},
		{
			name:    "same site none for front-channel logout",
			options: StoreOptions{SameSite: http.SameSiteNoneMode},
			want:    "auth_session=<value>; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=None",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := testCase.options
			options.Backend = newTestMemoryBackend(t, newTestClock())
			options.EncryptionKey = testEncryptionKey()
			store, err := NewStore(&options)
			require.NoError(t, err)
			recorder := httptest.NewRecorder()

			_, err = store.Start(t.Context(), recorder, newRequest(t))

			require.NoError(t, err)
			lines := recorder.Header().Values("Set-Cookie")
			require.Len(t, lines, 1)
			name, rest, _ := strings.Cut(lines[0], "=")
			value, attributes, _ := strings.Cut(rest, ";")
			decoded, err := base64.RawURLEncoding.DecodeString(value)
			require.NoError(t, err)
			require.Len(t, decoded, 32)
			require.Len(t, value, 43)
			require.Equal(t, testCase.want, name+"=<value>;"+attributes)
		})
	}
}

func TestStartRevokesThePreviousSession(t *testing.T) {
	store := newTestStore(t, newTestClock())
	previous, request := startSession(t, store)
	require.NoError(t, previous.Put(t.Context(), "app.key", []byte("value"), time.Hour))

	current, err := store.Start(t.Context(), httptest.NewRecorder(), request)

	require.NoError(t, err)
	require.NotEqual(t, previous.id, current.id)
	_, found, err := previous.Get(t.Context(), "app.key")
	require.NoError(t, err)
	require.False(t, found)
	err = previous.Put(t.Context(), "app.key", []byte("value"), time.Hour)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.ErrorIs(t, err, ErrSessionRevoked)
	require.NoError(t, current.Put(t.Context(), "app.key", []byte("value"), time.Hour))
}

// An attacker sending fresh well-formed cookies to a login route must not store anything (and so evict nobody).
func TestStartWithAnUnknownCookieWritesNothing(t *testing.T) {
	clock := newTestClock()
	backend, err := NewMemoryBackend(&MemoryBackendOptions{MaximumSessions: 4})
	require.NoError(t, err)
	backend.now = clock.now
	store := newTestStoreOn(t, clock, backend)
	victim := login(t, store, testIdentity())
	clock.advance(time.Hour)

	for range 4 {
		value, err := random.Token(cookieValueBytes)
		require.NoError(t, err)
		request := newRequest(t)
		request.Header.Set("Cookie", defaultCookieName+"="+value)
		_, err = store.Start(t.Context(), httptest.NewRecorder(), request)
		require.NoError(t, err)
	}

	require.Len(t, backend.sessions, 1)
	requireAuthenticated(t, store, victim)
}

// An attacker chaining login starts (each one revokes the previous login state) must not evict live
// sessions with markers: a marker lives no longer than the state it replaced and is never evicted, so the
// attacker's own Put fails once the backend is full.
func TestRevokedLoginStatesEvictNoSession(t *testing.T) {
	clock := newTestClock()
	backend, err := NewMemoryBackend(&MemoryBackendOptions{MaximumSessions: 3})
	require.NoError(t, err)
	backend.now = clock.now
	store := newTestStoreOn(t, clock, backend)
	victim := login(t, store, testIdentity())
	clock.advance(time.Hour)

	request := newRequest(t)
	var putError error
	for range 3 {
		recorder := httptest.NewRecorder()
		state, err := store.Start(t.Context(), recorder, request)
		require.NoError(t, err)
		putError = state.Put(t.Context(), "login.state", []byte("state"), 10*time.Minute)
		request = requestWithCookies(t, recorder)
	}

	require.Error(t, putError, "the backend is full of the attacker's markers")
	requireAuthenticated(t, store, victim)
}

func requireAuthenticated(t *testing.T, store *Store, request *http.Request) {
	t.Helper()
	current, err := store.Open(request)
	require.NoError(t, err)
	_, err = current.Identity(t.Context())
	require.NoError(t, err)
}

func TestStartFailsWhenThePreviousSessionCannotBeRevoked(t *testing.T) {
	clock := newTestClock()
	_, request := startSession(t, newTestStore(t, clock))
	store := newTestStoreOn(t, clock, failingBackend{})

	_, err := store.Start(t.Context(), httptest.NewRecorder(), request)
	require.ErrorIs(t, err, errBackendDown)

	_, err = store.Start(t.Context(), httptest.NewRecorder(), newRequest(t))
	require.NoError(t, err, "a request without a session revokes nothing")
}

func TestOpen(t *testing.T) {
	store := newTestStore(t, newTestClock())
	validValue := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	testCases := []struct {
		name    string
		cookie  string // Cookie request header
		wantErr bool
	}{
		{name: "valid cookie", cookie: "auth_session=" + validValue},
		{name: "no cookie", wantErr: true},
		{name: "other cookie name", cookie: "other=" + validValue, wantErr: true},
		{name: "empty value", cookie: "auth_session=", wantErr: true},
		{name: "not base64url", cookie: "auth_session=" + strings.Repeat("*", 43), wantErr: true},
		{name: "padded", cookie: "auth_session=" + validValue + "=", wantErr: true},
		{name: "too short", cookie: "auth_session=" + validValue[:42], wantErr: true},
		{name: "too long", cookie: "auth_session=" + validValue + "AAAA", wantErr: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := newRequest(t)
			if testCase.cookie != "" {
				request.Header.Set("Cookie", testCase.cookie)
			}

			current, err := store.Open(request)

			if testCase.wantErr {
				require.ErrorIs(t, err, auth.ErrUnauthenticated)
				return
			}
			require.NoError(t, err)
			require.Equal(t, sessionIDOf(validValue), current.id)
			require.Zero(t, current.startedAt)
		})
	}
}

func TestEnd(t *testing.T) {
	recording := &recordingBackend{Backend: newTestMemoryBackend(t, newTestClock())}
	store := newTestStoreOn(t, newTestClock(), recording)
	current, request := startSession(t, store)
	require.NoError(t, current.Put(t.Context(), "app.key", []byte("value"), time.Hour))
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	recorder := httptest.NewRecorder()

	require.NoError(t, store.End(canceled, recorder, request))

	requireExpiredCookie(t, recorder)
	require.Equal(t, []error{nil}, recording.revokeErrors, "revoked with a context the client cannot cancel")
	_, found, err := current.Get(t.Context(), "app.key")
	require.NoError(t, err)
	require.False(t, found)
	require.ErrorIs(t, current.Put(t.Context(), "app.key", []byte("value"), time.Hour), auth.ErrUnauthenticated)
	require.NoError(t, store.End(t.Context(), httptest.NewRecorder(), request), "ending twice")
}

func TestEndWithoutSessionOnlyExpiresTheCookie(t *testing.T) {
	store := newTestStoreOn(t, newTestClock(), failingBackend{})
	recorder := httptest.NewRecorder()

	require.NoError(t, store.End(t.Context(), recorder, newRequest(t)))

	requireExpiredCookie(t, recorder)
}

func TestEndReportsAFailedRevocationAndStillExpiresTheCookie(t *testing.T) {
	clock := newTestClock()
	_, request := startSession(t, newTestStore(t, clock))
	store := newTestStoreOn(t, clock, failingBackend{})
	recorder := httptest.NewRecorder()

	err := store.End(t.Context(), recorder, request)

	require.ErrorIs(t, err, errBackendDown)
	requireExpiredCookie(t, recorder)
}

func TestBackendSeesOnlyHashedIDsAndCiphertext(t *testing.T) {
	recording := &recordingBackend{Backend: newTestMemoryBackend(t, newTestClock())}
	store := newTestStoreOn(t, newTestClock(), recording)
	current, request := startSession(t, store)
	plaintext := "a very secret session value"

	require.NoError(t, current.Put(t.Context(), "app.secret", []byte(plaintext), time.Hour))

	cookie, err := request.Cookie("auth_session")
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(cookie.Value))
	require.Len(t, recording.puts, 1)
	put := recording.puts[0]
	require.Equal(t, hex.EncodeToString(sum[:]), put.sessionID)
	require.NotContains(t, put.sessionID, cookie.Value)
	require.Equal(t, "app.secret", put.key)
	require.Equal(t, time.Hour, put.ttl)
	require.NotContains(t, string(put.value), plaintext)
	require.Len(t, put.value, len(plaintext)+12+16, "nonce, ciphertext, tag")
}

func requireExpiredCookie(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	cookies := responseCookies(t, recorder)
	require.Len(t, cookies, 1)
	require.Equal(t, "auth_session", cookies[0].Name)
	require.Empty(t, cookies[0].Value)
	require.Negative(t, cookies[0].MaxAge)
	require.True(t, cookies[0].HttpOnly)
	require.True(t, cookies[0].Secure)
	require.Equal(t, "/", cookies[0].Path)
}
