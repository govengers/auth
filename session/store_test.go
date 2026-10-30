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
		name      string
		options   *StoreOptions
		wantError string
	}{
		{name: "nil options", options: nil, wantError: "Backend is required"},
		{name: "no backend", options: valid(func(options *StoreOptions) { options.Backend = nil }), wantError: "Backend is required"},
		{name: "no key", options: valid(func(options *StoreOptions) { options.EncryptionKey = nil }), wantError: "EncryptionKey has 0 bytes"},
		{name: "short key", options: valid(func(options *StoreOptions) { options.EncryptionKey = options.EncryptionKey[:31] }), wantError: "EncryptionKey has 31 bytes"},
		{name: "long key", options: valid(func(options *StoreOptions) { options.EncryptionKey = append(options.EncryptionKey, 'x') }), wantError: "EncryptionKey has 33 bytes"},
		{name: "maximum age below a second", options: valid(func(options *StoreOptions) { options.MaximumAge = 500 * time.Millisecond }), wantError: "below one second"},
		{name: "negative maximum age", options: valid(func(options *StoreOptions) { options.MaximumAge = -time.Hour }), wantError: "below one second"},
		{name: "same site default mode", options: valid(func(options *StoreOptions) { options.SameSite = http.SameSiteDefaultMode }), wantError: "SameSite must be Lax, Strict or None"},
		{name: "unknown same site", options: valid(func(options *StoreOptions) { options.SameSite = 9 }), wantError: "SameSite 9 is unknown"},
		{name: "same site none on an insecure cookie", options: valid(func(options *StoreOptions) {
			options.SameSite = http.SameSiteNoneMode
			options.InsecureCookie = true
		}), wantError: "SameSite None requires a Secure cookie"},
		{name: "relative cookie path", options: valid(func(options *StoreOptions) { options.CookiePath = "app" }), wantError: "CookiePath must start with"},
		{name: "cookie path with semicolon", options: valid(func(options *StoreOptions) { options.CookiePath = "/a;b" }), wantError: "in Cookie.Path"},
		{name: "cookie name with space", options: valid(func(options *StoreOptions) { options.CookieName = "bad name" }), wantError: "invalid Cookie.Name"},
		{name: "invalid cookie domain", options: valid(func(options *StoreOptions) { options.CookieDomain = "bad domain!" }), wantError: "invalid Cookie.Domain"},
		{name: "__Host- name on an insecure cookie", options: valid(func(options *StoreOptions) {
			options.CookieName, options.InsecureCookie = "__Host-app", true
		}), wantError: `a "__Host-" CookieName needs`},
		{name: "__Host- name with a domain", options: valid(func(options *StoreOptions) {
			options.CookieName, options.CookieDomain = "__host-app", "example.com"
		}), wantError: `a "__Host-" CookieName needs`},
		{name: "__Host- name on another path", options: valid(func(options *StoreOptions) {
			options.CookieName, options.CookiePath = "__Host-app", "/app"
		}), wantError: `a "__Host-" CookieName needs`},
		{name: "__Secure- name on an insecure cookie", options: valid(func(options *StoreOptions) {
			options.CookieName, options.InsecureCookie = "__Secure-app", true
		}), wantError: `a "__Secure-" CookieName needs a Secure cookie`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store, err := NewStore(testCase.options)
			require.ErrorContains(t, err, testCase.wantError)
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
	require.Equal(t, "__Host-auth_session", store.options.CookieName)
	require.Equal(t, "/", store.options.CookiePath)
	require.Equal(t, http.SameSiteLaxMode, store.options.SameSite)
	require.Equal(t, 24*time.Hour, store.MaximumAge())

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

func TestNewStoreNamesASecureHostOnlyCookieWithTheHostPrefix(t *testing.T) {
	testCases := []struct {
		name    string
		options StoreOptions
		want    string
	}{
		{name: "defaults", want: "__Host-auth_session"},
		{name: "own name", options: StoreOptions{CookieName: "app"}, want: "__Host-app"},
		{name: "insecure cookie", options: StoreOptions{InsecureCookie: true}, want: "auth_session"},
		{name: "domain cookie", options: StoreOptions{CookieDomain: "example.com"}, want: "auth_session"},
		{name: "path below the root", options: StoreOptions{CookiePath: "/app"}, want: "auth_session"},
		{name: "own __Host- prefix", options: StoreOptions{CookieName: "__Host-app"}, want: "__Host-app"},
		{name: "own __Host- prefix in another case", options: StoreOptions{CookieName: "__host-app"}, want: "__host-app"},
		{name: "own __Secure- prefix", options: StoreOptions{CookieName: "__Secure-app", CookieDomain: "example.com"}, want: "__Secure-app"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := testCase.options
			options.Backend = newTestMemoryBackend(t, newTestClock())
			options.EncryptionKey = testEncryptionKey()

			store, err := NewStore(&options)

			require.NoError(t, err)
			require.Equal(t, testCase.want, store.options.CookieName)
		})
	}
}

// A sibling subdomain can set a cookie of the bare name for the parent domain; the store must not read it.
func TestOpenIgnoresATossedCookieWithoutTheHostPrefix(t *testing.T) {
	store := newTestStore(t, newTestClock())
	_, request := startSession(t, store)
	cookie, err := request.Cookie("__Host-auth_session")
	require.NoError(t, err)
	tossed := newRequest(t)
	tossed.Header.Set("Cookie", "auth_session="+cookie.Value)

	_, err = store.Open(tossed)

	require.ErrorIs(t, err, auth.ErrUnauthenticated)
}

func TestStartSetsTheCookie(t *testing.T) {
	testCases := []struct {
		name    string
		options StoreOptions
		want    string // Set-Cookie header with the value replaced by <value>
	}{
		{
			name: "defaults",
			want: "__Host-auth_session=<value>; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax",
		},
		{
			name:    "configured",
			options: StoreOptions{CookieName: "app", CookieDomain: "example.com", CookiePath: "/app", SameSite: http.SameSiteStrictMode, InsecureCookie: true, MaximumAge: time.Hour},
			want:    "app=<value>; Path=/app; Domain=example.com; Max-Age=3600; HttpOnly; SameSite=Strict",
		},
		{
			name:    "secure domain cookie keeps its name",
			options: StoreOptions{CookieDomain: "example.com"},
			want:    "auth_session=<value>; Path=/; Domain=example.com; Max-Age=86400; HttpOnly; Secure; SameSite=Lax",
		},
		{
			name:    "same site none for front-channel logout",
			options: StoreOptions{SameSite: http.SameSiteNoneMode},
			want:    "__Host-auth_session=<value>; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=None",
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
	require.ErrorIs(t, err, ErrRevoked)
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
		request.Header.Set("Cookie", hostPrefix+defaultCookieName+"="+value)
		_, err = store.Start(t.Context(), httptest.NewRecorder(), request)
		require.NoError(t, err)
	}

	require.Len(t, backend.sessions, 1)
	requireAuthenticated(t, store, victim)
}

// A chain of login starts, each revoking the previous one's 10-minute state, fills a full memory backend
// with markers: it must neither block new sessions nor evict a real session expiring later.
func TestAFloodOfLoginStartsBlocksNoSession(t *testing.T) {
	clock := newTestClock()
	backend, err := NewMemoryBackend(&MemoryBackendOptions{MaximumSessions: 3})
	require.NoError(t, err)
	backend.now = clock.now
	store := newTestStoreOn(t, clock, backend)
	victim := login(t, store, testIdentity())
	clock.advance(time.Hour)

	request := newRequest(t)
	for range 10 {
		recorder := httptest.NewRecorder()
		state, err := store.Start(t.Context(), recorder, request)
		require.NoError(t, err)
		require.NoError(t, state.Put(t.Context(), "login.state", []byte("state"), 10*time.Minute))
		request = requestWithCookies(t, recorder)
	}

	state, _ := startSession(t, store)
	require.NoError(t, state.Put(t.Context(), "login.state", []byte("state"), 10*time.Minute), "a real login start gets a session")
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
		name      string
		cookie    string // Cookie request header
		wantError bool
	}{
		{name: "valid cookie", cookie: "__Host-auth_session=" + validValue},
		{name: "no cookie", wantError: true},
		{name: "other cookie name", cookie: "other=" + validValue, wantError: true},
		{name: "empty value", cookie: "__Host-auth_session=", wantError: true},
		{name: "not base64url", cookie: "__Host-auth_session=" + strings.Repeat("*", 43), wantError: true},
		{name: "padded", cookie: "__Host-auth_session=" + validValue + "=", wantError: true},
		{name: "too short", cookie: "__Host-auth_session=" + validValue[:42], wantError: true},
		{name: "too long", cookie: "__Host-auth_session=" + validValue + "AAAA", wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := newRequest(t)
			if testCase.cookie != "" {
				request.Header.Set("Cookie", testCase.cookie)
			}

			current, err := store.Open(request)

			if testCase.wantError {
				require.ErrorIs(t, err, auth.ErrUnauthenticated)
				return
			}
			require.NoError(t, err)
			require.Equal(t, sessionIDOf(validValue), current.id)
			require.Nil(t, current.start, "an opened session has no first save")
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

	before := time.Now()
	require.NoError(t, store.End(canceled, recorder, request))
	after := time.Now()

	requireExpiredCookie(t, recorder)
	require.Equal(t, []error{nil}, recording.revokeErrors, "revoked with a context the client cannot cancel")
	require.Len(t, recording.revokeDeadlines, 1)
	require.False(t, recording.revokeDeadlines[0].Before(before.Add(10*time.Second)), "but with its own 10 s timeout")
	require.False(t, recording.revokeDeadlines[0].After(after.Add(10*time.Second)), "but with its own 10 s timeout")
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

	cookie, err := request.Cookie("__Host-auth_session")
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
	require.Equal(t, "__Host-auth_session", cookies[0].Name)
	require.Empty(t, cookies[0].Value)
	require.Negative(t, cookies[0].MaxAge)
	require.True(t, cookies[0].HttpOnly)
	require.True(t, cookies[0].Secure)
	require.Equal(t, "/", cookies[0].Path)
}
