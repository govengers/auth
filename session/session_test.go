package session

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

func TestSessionValues(t *testing.T) {
	store := newTestStore(t, newTestClock())
	current, _ := startSession(t, store)
	ctx := t.Context()

	require.NoError(t, current.Put(ctx, "app.key", []byte("value"), time.Hour))

	value, found, err := current.Get(ctx, "app.key")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "value", string(value))
	value, found, err = current.Pop(ctx, "app.key")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "value", string(value))
	_, found, err = current.Pop(ctx, "app.key")
	require.NoError(t, err)
	require.False(t, found, "pop is single use")
	_, found, err = current.Get(ctx, "app.missing")
	require.NoError(t, err)
	require.False(t, found)
}

func TestSessionPutValidation(t *testing.T) {
	current, _ := startSession(t, newTestStore(t, newTestClock()))
	testCases := []struct {
		name string
		key  string
		ttl  time.Duration
	}{
		{name: "empty key", key: "", ttl: time.Hour},
		{name: "zero ttl", key: "app.key", ttl: 0},
		{name: "negative ttl", key: "app.key", ttl: -time.Second},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.ErrorContains(t, current.Put(t.Context(), testCase.key, []byte("value"), testCase.ttl), "ttl must be positive")
		})
	}
}

func TestSessionPropagatesBackendErrors(t *testing.T) {
	store := newTestStoreOn(t, newTestClock(), failingBackend{})
	current, err := store.Start(t.Context(), httptest.NewRecorder(), newRequest(t))
	require.NoError(t, err)
	ctx := t.Context()

	require.ErrorIs(t, current.Put(ctx, "app.key", []byte("value"), time.Hour), errBackendDown)
	_, _, err = current.Get(ctx, "app.key")
	require.ErrorIs(t, err, errBackendDown)
	_, _, err = current.Pop(ctx, "app.key")
	require.ErrorIs(t, err, errBackendDown)
	_, err = current.Identity(ctx)
	require.ErrorIs(t, err, errBackendDown)
	require.NotErrorIs(t, err, auth.ErrUnauthenticated, "a backend failure is no refusal")
	require.ErrorIs(t, current.SaveIdentity(ctx, testIdentity()), errBackendDown)
}

func TestSealedValuesAreBoundToSessionKeyAndStoreKey(t *testing.T) {
	clock := newTestClock()
	backend := newTestMemoryBackend(t, clock)
	store := newTestStoreOn(t, clock, backend)
	current, _ := startSession(t, store)
	other, _ := startSession(t, store)
	ctx := t.Context()
	require.NoError(t, current.Put(ctx, "app.a", []byte("value"), time.Hour))
	sealed, found, err := backend.Get(ctx, current.id, "app.a")
	require.NoError(t, err)
	require.True(t, found)
	otherKey := testEncryptionKey()
	otherKey[0] ^= 0xff
	otherStore, err := NewStore(&StoreOptions{Backend: backend, EncryptionKey: otherKey})
	require.NoError(t, err)
	tampered := append([]byte{}, sealed...)
	tampered[len(tampered)-1] ^= 0x01
	testCases := []struct {
		name    string
		reader  Session
		key     string
		written []byte
	}{
		{name: "copied to another key", reader: current, key: "app.b", written: sealed},
		{name: "copied to another session", reader: other, key: "app.a", written: sealed},
		{name: "tampered", reader: current, key: "app.c", written: tampered},
		{name: "truncated", reader: current, key: "app.d", written: sealed[:10]},
		{name: "empty", reader: current, key: "app.e", written: []byte{}},
		{name: "read with another store key", reader: Session{store: otherStore, id: current.id}, key: "app.a"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.written != nil {
				require.NoError(t, backend.Put(ctx, testCase.reader.id, testCase.key, testCase.written, time.Hour))
			}

			value, found, err := testCase.reader.Get(ctx, testCase.key)

			require.NoError(t, err)
			require.False(t, found)
			require.Nil(t, value)
		})
	}
}

func TestSaveIdentityRoundTrip(t *testing.T) {
	store := newTestStore(t, newTestClock())
	identity := &auth.Identity{
		Provider:   "keycloak",
		Subject:    "subject-1",
		UserID:     uuid.MustParse("6f1c2a52-6c43-4c5e-9d3a-0f3d1c2b4a5e"),
		Username:   "ada",
		Active:     true,
		Roles:      []string{auth.RoleAdmin},
		Groups:     []string{"/engineering"},
		Attributes: map[string][]string{"department": {"research"}},
		Claims:     map[string]any{"sid": "abc"},
		Data:       map[string]any{"tenant": "a"},
		Impersonator: &auth.Identity{
			Provider: "keycloak", Subject: "admin-1", Active: true, Roles: []string{auth.RoleAdmin},
		},
	}
	request := login(t, store, identity)
	current, err := store.Open(request)
	require.NoError(t, err)

	stored, err := current.Identity(t.Context())

	require.NoError(t, err)
	require.Equal(t, identity, stored)
	require.NotSame(t, identity, stored)
}

func TestSaveIdentityRefusals(t *testing.T) {
	clock := newTestClock()
	store := newTestStore(t, clock)
	ctx := t.Context()
	started, request := startSession(t, store)
	opened, err := store.Open(request)
	require.NoError(t, err)

	require.ErrorContains(t, started.SaveIdentity(ctx, nil), "identity is nil")
	unencodable := testIdentity()
	unencodable.Data = map[string]any{"channel": make(chan int)}
	require.ErrorContains(t, started.SaveIdentity(ctx, unencodable), "encode session identity")
	require.ErrorIs(t, opened.SaveIdentity(ctx, testIdentity()), auth.ErrUnauthenticated, "a session opened from a cookie never begins a lifetime")
	_, err = opened.Identity(ctx)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)

	require.NoError(t, started.SaveIdentity(ctx, testIdentity()))
	require.NoError(t, opened.SaveIdentity(ctx, testIdentity()), "an authenticated session may be saved again")

	require.NoError(t, store.End(ctx, httptest.NewRecorder(), request))
	require.ErrorIs(t, opened.SaveIdentity(ctx, testIdentity()), auth.ErrUnauthenticated, "revoked")
	require.ErrorIs(t, started.SaveIdentity(ctx, testIdentity()), auth.ErrUnauthenticated, "revoked, even for the started handle")
}

func TestIdentityExpiresAbsolutely(t *testing.T) {
	clock := newTestClock()
	store := newTestStore(t, clock)
	ctx := t.Context()
	request := login(t, store, testIdentity())
	current, err := store.Open(request)
	require.NoError(t, err)
	authenticatedAt := clock.now()

	clock.advance(23 * time.Hour)
	updated := testIdentity()
	updated.Roles = []string{"writer"}
	require.NoError(t, current.SaveIdentity(ctx, updated))

	envelope, err := current.envelope(ctx)
	require.NoError(t, err)
	require.Equal(t, authenticatedAt, envelope.AuthenticatedAt, "later saves keep authenticatedAt")
	require.Equal(t, clock.now(), envelope.RefreshedAt)
	require.Equal(t, updated, envelope.Identity)

	clock.advance(time.Hour - time.Second)
	_, err = current.Identity(ctx)
	require.NoError(t, err, "one second before the absolute expiry")

	clock.advance(2 * time.Second)
	_, err = current.Identity(ctx)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.ErrorIs(t, current.SaveIdentity(ctx, updated), auth.ErrUnauthenticated, "an expired session gets no fresh lifetime")
}

// A handle returned by Start, retained or copied past the absolute expiry, must not begin a second lifetime.
func TestStartedHandleCannotRestartAnExpiredLifetime(t *testing.T) {
	clock := newTestClock()
	store := newTestStore(t, clock)
	ctx := t.Context()
	current, request := startSession(t, store)
	copied := current
	require.NoError(t, current.SaveIdentity(ctx, testIdentity()))

	clock.advance(24*time.Hour + time.Second)

	require.ErrorIs(t, current.SaveIdentity(ctx, testIdentity()), auth.ErrUnauthenticated, "retained handle")
	require.ErrorIs(t, copied.SaveIdentity(ctx, testIdentity()), auth.ErrUnauthenticated, "copied handle")
	opened, err := store.Open(request)
	require.NoError(t, err)
	_, err = opened.Identity(ctx)
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "the original cookie stays logged out")
}

func TestIdentityChecksTheEnvelopeExpiry(t *testing.T) {
	clock := newTestClock()
	store := newTestStore(t, clock)
	current, _ := startSession(t, store)
	putEnvelope(t, current, identityEnvelope{Identity: testIdentity(), AuthenticatedAt: clock.now().Add(-25 * time.Hour)})

	_, err := current.Identity(t.Context())

	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.ErrorContains(t, err, "session expired")
}

func TestIdentityRefusesUnreadableEnvelopes(t *testing.T) {
	testCases := []struct {
		name    string
		encoded string
	}{
		{name: "not JSON", encoded: "not json"},
		{name: "no identity", encoded: `{"authenticatedAt":"2026-10-29T12:00:00Z"}`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			current, _ := startSession(t, newTestStore(t, newTestClock()))
			require.NoError(t, current.Put(t.Context(), identityKey, []byte(testCase.encoded), time.Hour))

			_, err := current.Identity(t.Context())

			require.ErrorIs(t, err, auth.ErrUnauthenticated)
			require.ErrorContains(t, err, "unreadable session identity")
		})
	}
}

func putEnvelope(t *testing.T, current Session, envelope identityEnvelope) {
	t.Helper()
	encoded, err := json.Marshal(envelope)
	require.NoError(t, err)
	require.NoError(t, current.Put(t.Context(), identityKey, encoded, time.Hour))
}

func TestSwapIdentity(t *testing.T) {
	clock := newTestClock()
	store := newTestStore(t, clock)
	ctx := t.Context()
	authenticatedAt := clock.now()
	request := login(t, store, testIdentity())
	current, err := store.Open(request)
	require.NoError(t, err)
	previous, err := current.Identity(ctx)
	require.NoError(t, err)
	updated := testIdentity()
	updated.Teams = []string{"acme/admins"}
	clock.advance(time.Hour)

	swapped, err := current.SwapIdentity(ctx, previous, updated)

	require.NoError(t, err)
	require.True(t, swapped)
	envelope, err := current.envelope(ctx)
	require.NoError(t, err)
	require.Equal(t, updated, envelope.Identity)
	require.Equal(t, authenticatedAt, envelope.AuthenticatedAt, "the lifetime is kept")
	require.Equal(t, clock.now(), envelope.RefreshedAt)

	swapped, err = current.SwapIdentity(ctx, previous, testIdentity())
	require.NoError(t, err)
	require.False(t, swapped, "the session holds another identity than previous")
	stored, err := current.Identity(ctx)
	require.NoError(t, err)
	require.Equal(t, updated, stored)

	withEmptySlices := updated.Clone()
	withEmptySlices.OIDCRoles = []string{}
	swapped, err = current.SwapIdentity(ctx, withEmptySlices, testIdentity())
	require.NoError(t, err)
	require.True(t, swapped, "previous is compared in its stored form")
}

// A save made between SwapIdentity's read and its swap wins.
func TestSwapIdentityLosesToASaveAfterItsRead(t *testing.T) {
	store := newTestStore(t, newTestClock())
	ctx := t.Context()
	request := login(t, store, testIdentity())
	saved := testIdentity()
	saved.Active = false
	store.options.Backend = &beforeSwapBackend{Backend: store.options.Backend, beforeSwap: func() {
		concurrent, err := store.Open(request)
		require.NoError(t, err)
		require.NoError(t, concurrent.SaveIdentity(ctx, saved))
	}}
	current, err := store.Open(request)
	require.NoError(t, err)

	swapped, err := current.SwapIdentity(ctx, testIdentity(), testIdentity())

	require.NoError(t, err)
	require.False(t, swapped)
	stored, err := current.Identity(ctx)
	require.NoError(t, err)
	require.Equal(t, saved, stored)
}

func TestSwapIdentityRefusals(t *testing.T) {
	clock := newTestClock()
	store := newTestStore(t, clock)
	ctx := t.Context()
	request := login(t, store, testIdentity())
	current, err := store.Open(request)
	require.NoError(t, err)
	unencodable := testIdentity()
	unencodable.Data = map[string]any{"channel": make(chan int)}

	_, err = current.SwapIdentity(ctx, testIdentity(), nil)
	require.ErrorContains(t, err, "identity is nil")
	_, err = current.SwapIdentity(ctx, unencodable, testIdentity())
	require.ErrorContains(t, err, "compare session identity")
	_, err = current.SwapIdentity(ctx, testIdentity(), unencodable)
	require.ErrorContains(t, err, "encode session identity")

	clock.advance(24*time.Hour + time.Second)
	_, err = current.SwapIdentity(ctx, testIdentity(), testIdentity())
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "expired")

	revoked := login(t, store, testIdentity())
	require.NoError(t, store.End(ctx, httptest.NewRecorder(), revoked))
	ended, err := store.Open(revoked)
	require.NoError(t, err)
	_, err = ended.SwapIdentity(ctx, testIdentity(), testIdentity())
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "revoked")
}
