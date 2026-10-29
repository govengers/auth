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

var errBackendDown = errors.New("backend down")

func testEncryptionKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

type testClock struct {
	mutex   sync.Mutex
	current time.Time
}

func newTestClock() *testClock {
	return &testClock{current: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.current
}

func (c *testClock) advance(duration time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.current = c.current.Add(duration)
}

func newTestMemoryBackend(t *testing.T, clock *testClock) *MemoryBackend {
	t.Helper()
	backend, err := NewMemoryBackend(nil)
	require.NoError(t, err)
	backend.now = clock.now
	return backend
}

// newTestStore returns a store on a memory backend, both on clock.
func newTestStore(t *testing.T, clock *testClock) *Store {
	t.Helper()
	return newTestStoreOn(t, clock, newTestMemoryBackend(t, clock))
}

func newTestStoreOn(t *testing.T, clock *testClock, backend Backend) *Store {
	t.Helper()
	store, err := NewStore(&StoreOptions{Backend: backend, EncryptionKey: testEncryptionKey()})
	require.NoError(t, err)
	store.now = clock.now
	return store
}

// startSession starts a session and returns it with a request that carries its cookie.
func startSession(t *testing.T, store *Store) (Session, *http.Request) {
	t.Helper()
	recorder := httptest.NewRecorder()
	current, err := store.Start(t.Context(), recorder, newRequest(t))
	require.NoError(t, err)
	return current, requestWithCookies(t, recorder)
}

// login starts a session, saves identity in it and returns a request that carries its cookie.
func login(t *testing.T, store *Store, identity *auth.Identity) *http.Request {
	t.Helper()
	current, request := startSession(t, store)
	require.NoError(t, current.SaveIdentity(t.Context(), identity))
	return request
}

func newRequest(t *testing.T) *http.Request {
	t.Helper()
	return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
}

// requestWithCookies returns a request carrying the live cookies the recorder's response set, as a browser would.
func requestWithCookies(t *testing.T, recorder *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	request := newRequest(t)
	for _, cookie := range responseCookies(t, recorder) {
		if cookie.MaxAge >= 0 {
			request.AddCookie(cookie)
		}
	}
	return request
}

func responseCookies(t *testing.T, recorder *httptest.ResponseRecorder) []*http.Cookie {
	t.Helper()
	cookies := []*http.Cookie{}
	for _, line := range recorder.Header().Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(line)
		require.NoError(t, err)
		cookies = append(cookies, cookie)
	}
	return cookies
}

func testIdentity() *auth.Identity {
	return &auth.Identity{Provider: "password", Subject: "user-1", Username: "ada", Active: true, Roles: []string{"reader"}}
}

// recordingBackend records what reaches the backend and passes it on.
type recordingBackend struct {
	Backend
	mutex           sync.Mutex
	puts            []recordedPut
	revokeErrors    []error
	revokeDeadlines []time.Time // zero when the context had none
}

type recordedPut struct {
	sessionID string
	key       string
	value     []byte
	ttl       time.Duration
}

func (b *recordingBackend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	b.mutex.Lock()
	b.puts = append(b.puts, recordedPut{sessionID: sessionID, key: key, value: value, ttl: ttl})
	b.mutex.Unlock()
	return b.Backend.Put(ctx, sessionID, key, value, ttl)
}

func (b *recordingBackend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	b.mutex.Lock()
	b.revokeErrors = append(b.revokeErrors, ctx.Err())
	deadline, _ := ctx.Deadline()
	b.revokeDeadlines = append(b.revokeDeadlines, deadline)
	b.mutex.Unlock()
	return b.Backend.Revoke(ctx, sessionID, ttl)
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
