package password

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

var testEncryptionKey = []byte("0123456789abcdef0123456789abcdef")

const testSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

type testClock struct {
	mutex   sync.Mutex
	current time.Time
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

// take returns the outcomes recorded since the last take.
func (r *outcomeRecorder) take() []auth.Outcome {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	outcomes := r.outcomes
	r.outcomes = nil
	return outcomes
}

// last returns the only outcome recorded since the last take.
func (r *outcomeRecorder) last(t *testing.T) auth.Outcome {
	t.Helper()
	outcomes := r.take()
	require.Len(t, outcomes, 1)
	return outcomes[0]
}

type fixture struct {
	clock    *testClock
	storage  *MemoryStorage
	backend  *session.MemoryBackend
	sessions *session.Store
	provider *Provider
	serveMux *http.ServeMux
	outcomes *outcomeRecorder
}

// newFixture builds a provider on options with a memory session store, a MemoryStorage (unless options has a
// Storage), cheap hash parameters, a test clock and an outcome recorder, its routes on a ServeMux.
func newFixture(t *testing.T, options Options) *fixture {
	t.Helper()
	backend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	sessions, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: testEncryptionKey})
	require.NoError(t, err)
	fixture := &fixture{
		clock:    &testClock{current: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)},
		storage:  NewMemoryStorage(),
		backend:  backend,
		sessions: sessions,
		outcomes: &outcomeRecorder{},
		serveMux: http.NewServeMux(),
	}
	if options.Storage == nil {
		options.Storage = fixture.storage
	}
	options.Sessions = sessions
	options.Observer = fixture.outcomes.observe
	resolved, err := resolveOptions(options)
	require.NoError(t, err)
	resolved.HashParameters = testParameters
	fixture.provider, err = newProvider(resolved)
	require.NoError(t, err)
	fixture.provider.now = fixture.clock.now
	auth.RegisterRoutes(fixture.serveMux, fixture.provider.Routes())
	return fixture
}

func totpOptions() Options {
	return Options{TOTP: TOTPOptions{Enabled: true, Issuer: "Example"}}
}

// createUser stores a user with testPassword; empty username or email stay unset.
func (f *fixture) createUser(t *testing.T, username, email string) *User {
	t.Helper()
	hash, err := Hash(testPassword, testParameters)
	require.NoError(t, err)
	user := &User{ID: uuid.New(), PasswordHash: hash}
	if username != "" {
		user.Username = &username
	}
	if email != "" {
		user.Email = &email
	}
	require.NoError(t, f.storage.CreateUser(t.Context(), user))
	return user
}

// createTOTPUser stores a user with testPassword, TOTP on testSecret and the returned backup codes.
func (f *fixture) createTOTPUser(t *testing.T, username string) (*User, []string) {
	t.Helper()
	user := f.createUser(t, username, "")
	codes := []string{"1111111111", "2222222222", "3333333333"}
	hashes := make([]string, 0, len(codes))
	for _, code := range codes {
		hash, err := Hash(code, testParameters)
		require.NoError(t, err)
		hashes = append(hashes, hash)
	}
	requireSetTOTP(t, f.storage, user.ID, testSecret, hashes)
	return user, codes
}

// requireSetTOTP enables TOTP for a user of storage who has it disabled.
func requireSetTOTP(t *testing.T, storage Storage, id uuid.UUID, secret string, hashes []string) {
	t.Helper()
	enabled, err := storage.SetTOTP(t.Context(), id, secret, hashes)
	require.NoError(t, err)
	require.True(t, enabled)
}

// code returns the TOTP code of secret at the fixture's time plus offset, on the provider's period and digits.
func (f *fixture) code(t *testing.T, secret string, offset time.Duration) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, f.clock.now().Add(offset), totp.ValidateOpts{
		Period: f.provider.options.TOTP.Period,
		Digits: otp.Digits(f.provider.options.TOTP.Digits),
	})
	require.NoError(t, err)
	return code
}

func (f *fixture) storedUser(t *testing.T, id uuid.UUID) *User {
	t.Helper()
	user, err := f.storage.GetUserByID(t.Context(), id)
	require.NoError(t, err)
	return user
}

// client is a browser: it keeps the cookies the provider sets and sends them back.
type client struct {
	t       *testing.T
	handler http.Handler
	cookies map[string]*http.Cookie
}

func (f *fixture) newClient(t *testing.T) *client {
	t.Helper()
	return &client{t: t, handler: f.serveMux, cookies: map[string]*http.Cookie{}}
}

// clientWith returns a client whose session holds identity.
func (f *fixture) clientWith(t *testing.T, identity *auth.Identity) *client {
	t.Helper()
	browser := f.newClient(t)
	recorder := httptest.NewRecorder()
	current, err := f.sessions.Start(t.Context(), recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	require.NoError(t, err)
	require.NoError(t, current.SaveIdentity(t.Context(), identity))
	browser.keep(recorder)
	return browser
}

// copy returns a client with the same cookies, e.g. an attacker replaying a captured cookie.
func (c *client) copy() *client {
	return &client{t: c.t, handler: c.handler, cookies: maps.Clone(c.cookies)}
}

// post sends body as JSON; a string body is sent as it is.
func (c *client) post(path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.send(c.postRequest(path, body))
}

// postRequest returns the request post sends, without cookies.
func (c *client) postRequest(path string, body any) *http.Request {
	c.t.Helper()
	encoded, isText := body.(string)
	if !isText {
		marshalled, err := json.Marshal(body)
		require.NoError(c.t, err)
		encoded = string(marshalled)
	}
	request := httptest.NewRequestWithContext(c.t.Context(), http.MethodPost, path, bytes.NewBufferString(encoded))
	request.Header.Set("Content-Type", "application/json")
	return request
}

// postStatus sends a request of postRequest and returns only its status; it neither keeps cookies nor fails the
// test, so it may run off the test goroutine (postRequest may not).
func (c *client) postStatus(request *http.Request) int {
	for _, cookie := range c.cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	c.handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func (c *client) get(path string) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.send(httptest.NewRequestWithContext(c.t.Context(), http.MethodGet, path, nil))
}

func (c *client) send(request *http.Request) *httptest.ResponseRecorder {
	c.t.Helper()
	for _, cookie := range c.cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	c.handler.ServeHTTP(recorder, request)
	c.keep(recorder)
	return recorder
}

func (c *client) keep(recorder *httptest.ResponseRecorder) {
	c.t.Helper()
	for _, line := range recorder.Header().Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(line)
		require.NoError(c.t, err)
		if cookie.MaxAge < 0 {
			delete(c.cookies, cookie.Name)
			continue
		}
		c.cookies[cookie.Name] = cookie
	}
}

func (c *client) login(identifier string) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.post("/auth/password/login", map[string]any{"identifier": identifier, "password": testPassword})
}

func (c *client) hasSession() bool {
	_, found := c.cookies["auth_session"]
	return found
}

func decodeBody[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var body T
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&body))
	return body
}

// requireRefusal asserts status, the response code and no-store caching.
func requireRefusal(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	require.Equal(t, status, recorder.Code, recorder.Body.String())
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.Equal(t, code, decodeBody[auth.ErrorResponse](t, recorder).Code)
}

// requireIdentity asserts a 2xx IdentityResponse for user.
func requireIdentity(t *testing.T, recorder *httptest.ResponseRecorder, status int, user *User) auth.IdentityResponse {
	t.Helper()
	require.Equal(t, status, recorder.Code, recorder.Body.String())
	response := decodeBody[auth.IdentityResponse](t, recorder)
	require.Equal(t, "password", response.Provider)
	require.Equal(t, user.ID.String(), response.Subject)
	require.Equal(t, user.ID.String(), response.UserID)
	return response
}

// sessionIdentity returns the identity stored in the client's session, or the error reading it.
func (f *fixture) sessionIdentity(t *testing.T, browser *client) (*auth.Identity, error) {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	for _, cookie := range browser.cookies {
		request.AddCookie(cookie)
	}
	current, err := f.sessions.Open(request)
	if err != nil {
		return nil, err
	}
	return current.Identity(t.Context())
}

// failingStorage fails the operation named in failing and delegates everything else.
type failingStorage struct {
	*MemoryStorage
	failing string
}

var errStorageDown = errors.New("storage down")

func (s *failingStorage) fail(operation string) error {
	if s.failing == operation {
		return errStorageDown
	}
	return nil
}

func (s *failingStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	if err := s.fail("GetUserByUsername"); err != nil {
		return nil, err
	}
	return s.MemoryStorage.GetUserByUsername(ctx, username)
}

func (s *failingStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	if err := s.fail("GetUserByID"); err != nil {
		return nil, err
	}
	return s.MemoryStorage.GetUserByID(ctx, id)
}

func (s *failingStorage) CreateUser(ctx context.Context, user *User) error {
	if err := s.fail("CreateUser"); err != nil {
		return err
	}
	return s.MemoryStorage.CreateUser(ctx, user)
}

func (s *failingStorage) UpdatePasswordHash(ctx context.Context, id uuid.UUID, currentHash, newHash string) error {
	if err := s.fail("UpdatePasswordHash"); err != nil {
		return err
	}
	return s.MemoryStorage.UpdatePasswordHash(ctx, id, currentHash, newHash)
}

func (s *failingStorage) ConsumeTOTPAttempt(ctx context.Context, id uuid.UUID, maximum int) (int, error) {
	if err := s.fail("ConsumeTOTPAttempt"); err != nil {
		return 0, err
	}
	return s.MemoryStorage.ConsumeTOTPAttempt(ctx, id, maximum)
}

func (s *failingStorage) ResetTOTPAttempts(ctx context.Context, id uuid.UUID) error {
	if err := s.fail("ResetTOTPAttempts"); err != nil {
		return err
	}
	return s.MemoryStorage.ResetTOTPAttempts(ctx, id)
}

func (s *failingStorage) ConsumeTOTPStep(ctx context.Context, id uuid.UUID, step time.Time) (bool, error) {
	if err := s.fail("ConsumeTOTPStep"); err != nil {
		return false, err
	}
	return s.MemoryStorage.ConsumeTOTPStep(ctx, id, step)
}

func (s *failingStorage) ConsumeBackupCode(ctx context.Context, id uuid.UUID, hash string) (bool, error) {
	if err := s.fail("ConsumeBackupCode"); err != nil {
		return false, err
	}
	return s.MemoryStorage.ConsumeBackupCode(ctx, id, hash)
}

func (s *failingStorage) SetTOTP(ctx context.Context, id uuid.UUID, secret string, backupCodeHashes []string) (bool, error) {
	if err := s.fail("SetTOTP"); err != nil {
		return false, err
	}
	return s.MemoryStorage.SetTOTP(ctx, id, secret, backupCodeHashes)
}

func (s *failingStorage) ClearTOTP(ctx context.Context, id uuid.UUID) error {
	if err := s.fail("ClearTOTP"); err != nil {
		return err
	}
	return s.MemoryStorage.ClearTOTP(ctx, id)
}

// failStorage makes the provider's storage fail operation from now on.
func (f *fixture) failStorage(operation string) {
	f.provider.options.Storage = &failingStorage{MemoryStorage: f.storage, failing: operation}
}

// failingBackend is a session backend that fails the operations named in failing, every operation when it names
// none, and delegates the others.
type failingBackend struct {
	session.Backend
	failing []string
}

func (b *failingBackend) fails(operation string) bool {
	return len(b.failing) == 0 || slices.Contains(b.failing, operation)
}

func (b *failingBackend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	if b.fails("Put") {
		return errStorageDown
	}
	return b.Backend.Put(ctx, sessionID, key, value, ttl)
}

func (b *failingBackend) Get(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if b.fails("Get") {
		return nil, false, errStorageDown
	}
	return b.Backend.Get(ctx, sessionID, key)
}

func (b *failingBackend) Pop(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if b.fails("Pop") {
		return nil, false, errStorageDown
	}
	return b.Backend.Pop(ctx, sessionID, key)
}

func (b *failingBackend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	if b.fails("Revoke") {
		return errStorageDown
	}
	return b.Backend.Revoke(ctx, sessionID, ttl)
}

// failSessions moves the provider onto a store over the same sessions whose backend fails operations (every one
// when none is named) from now on.
func (f *fixture) failSessions(t *testing.T, operations ...string) {
	t.Helper()
	f.useBackend(t, &failingBackend{Backend: f.backend, failing: operations})
}

// useBackend moves the provider onto a store over the same sessions on backend, which wraps the fixture's.
func (f *fixture) useBackend(t *testing.T, backend session.Backend) {
	t.Helper()
	sessions, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: testEncryptionKey})
	require.NoError(t, err)
	f.provider.options.Sessions = sessions
}

// cancellableBackend is a session backend that fails a read on a cancelled context, like a network backend.
type cancellableBackend struct {
	session.Backend
}

func (b cancellableBackend) Get(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return b.Backend.Get(ctx, sessionID, key)
}
