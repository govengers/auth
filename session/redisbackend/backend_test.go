package redisbackend_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/backendtest"
	"github.com/govengers/auth/session"
	"github.com/govengers/auth/session/redisbackend"
)

// newRedis starts a miniredis server and returns a client on it; the client is closed with the test.
func newRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1, DialerRetries: 1})
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func newBackend(t *testing.T, keyPrefix string) (*redisbackend.Backend, *miniredis.Miniredis) {
	t.Helper()
	server, client := newRedis(t)
	backend, err := redisbackend.New(&redisbackend.Options{Client: client, KeyPrefix: keyPrefix})
	require.NoError(t, err)
	return backend, server
}

func TestBackendConformance(t *testing.T) {
	backendtest.Run(t, func(t *testing.T) (session.Backend, func(time.Duration)) {
		backend, server := newBackend(t, "")
		return backend, server.FastForward
	})
}

func TestNew(t *testing.T) {
	_, client := newRedis(t)
	testCases := []struct {
		name    string
		options *redisbackend.Options
		wantErr string
	}{
		{name: "nil options", options: nil, wantErr: "options are required"},
		{name: "missing client", options: &redisbackend.Options{}, wantErr: "Client is required"},
		{name: "opening brace in prefix", options: &redisbackend.Options{Client: client, KeyPrefix: "a{b"}, wantErr: "must not contain"},
		{name: "closing brace in prefix", options: &redisbackend.Options{Client: client, KeyPrefix: "a}b"}, wantErr: "must not contain"},
		{name: "defaults", options: &redisbackend.Options{Client: client}},
		{name: "custom prefix", options: &redisbackend.Options{Client: client, KeyPrefix: "app:sessions"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var original redisbackend.Options
			if testCase.options != nil {
				original = *testCase.options
			}

			backend, err := redisbackend.New(testCase.options)

			if testCase.wantErr != "" {
				require.ErrorContains(t, err, testCase.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, backend)
			require.Equal(t, original, *testCase.options, "caller's options untouched")
		})
	}
}

func TestKeyLayout(t *testing.T) {
	testCases := []struct {
		name       string
		keyPrefix  string
		wantPrefix string
	}{
		{name: "default prefix", keyPrefix: "", wantPrefix: "session"},
		{name: "custom prefix", keyPrefix: "app:sessions", wantPrefix: "app:sessions"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend, server := newBackend(t, testCase.keyPrefix)
			ctx := t.Context()
			index := testCase.wantPrefix + ":{s1}"
			value := index + ":identity"

			require.NoError(t, backend.Put(ctx, "s1", "identity", []byte("sealed"), time.Hour))

			require.ElementsMatch(t, []string{index, value}, server.Keys())
			stored, err := server.Get(value)
			require.NoError(t, err)
			require.Equal(t, "sealed", stored)
			members, err := server.SMembers(index)
			require.NoError(t, err)
			require.Equal(t, []string{value}, members)
			require.Equal(t, time.Hour, server.TTL(value))
			require.Equal(t, time.Hour, server.TTL(index))

			require.NoError(t, backend.Revoke(ctx, "s1", time.Minute))

			marker := index + "#revoked"
			require.Equal(t, []string{marker}, server.Keys(), "revoke leaves only the marker")
			require.Equal(t, time.Minute, server.TTL(marker))
		})
	}
}

// Every key of a session carries the session ID as hash tag, so the scripts stay on one cluster slot.
func TestKeysOfOneSessionShareTheHashTag(t *testing.T) {
	backend, server := newBackend(t, "")
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s1", "a", []byte("1"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s1", "b:c", []byte("2"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s2", "a", []byte("3"), time.Hour))
	require.NoError(t, backend.Revoke(ctx, "s3", time.Hour))

	for _, key := range server.Keys() {
		sessionID := strings.TrimPrefix(key, "session:{")
		sessionID, _, found := strings.Cut(sessionID, "}")
		require.True(t, found, key)
		require.Equal(t, sessionID, hashTag(t, key), key)
	}
	require.Len(t, server.Keys(), 6, "s1: index and two values, s2: index and value, s3: marker")
}

// hashTag returns the part Redis Cluster hashes: between the first '{' and the next '}'.
func hashTag(t *testing.T, key string) string {
	t.Helper()
	_, afterOpen, found := strings.Cut(key, "{")
	require.True(t, found, key)
	tag, _, found := strings.Cut(afterOpen, "}")
	require.True(t, found, key)
	return tag
}

func TestRevocationMarkerBlocksPut(t *testing.T) {
	backend, server := newBackend(t, "")
	ctx := t.Context()
	require.NoError(t, backend.Revoke(ctx, "s1", time.Hour))

	err := backend.Put(ctx, "s1", "key", []byte("value"), time.Hour)

	require.ErrorIs(t, err, session.ErrSessionRevoked)
	require.False(t, server.Exists("session:{s1}:key"), "a refused put writes nothing")
	require.False(t, server.Exists("session:{s1}"), "a refused put indexes nothing")
}

func TestPutExtendsButNeverShortensTheIndexTTL(t *testing.T) {
	backend, server := newBackend(t, "")
	ctx := t.Context()

	require.NoError(t, backend.Put(ctx, "s", "short", []byte("1"), time.Minute))
	require.Equal(t, time.Minute, server.TTL("session:{s}"))
	require.NoError(t, backend.Put(ctx, "s", "long", []byte("2"), time.Hour))
	require.Equal(t, time.Hour, server.TTL("session:{s}"))
	require.NoError(t, backend.Put(ctx, "s", "short", []byte("3"), time.Minute))
	require.Equal(t, time.Hour, server.TTL("session:{s}"))
}

func TestPopRemovesTheIndexEntry(t *testing.T) {
	backend, server := newBackend(t, "")
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s", "other", []byte("kept"), time.Hour))

	_, found, err := backend.Pop(ctx, "s", "key")

	require.NoError(t, err)
	require.True(t, found)
	members, err := server.SMembers("session:{s}")
	require.NoError(t, err)
	require.Equal(t, []string{"session:{s}:other"}, members)
}

func TestBinaryValuesRoundTrip(t *testing.T) {
	backend, _ := newBackend(t, "")
	ctx := t.Context()
	sealed := []byte{0x00, 0xff, 0x0a, 0x80, 'x', 0x00}
	require.NoError(t, backend.Put(ctx, "s", "get", sealed, time.Hour))
	require.NoError(t, backend.Put(ctx, "s", "pop", sealed, time.Hour))

	read, found, err := backend.Get(ctx, "s", "get")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, sealed, read)

	popped, found, err := backend.Pop(ctx, "s", "pop")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, sealed, popped)
}

func TestSubMillisecondTTLIsStoredAsOneMillisecond(t *testing.T) {
	backend, server := newBackend(t, "")
	ctx := t.Context()

	require.NoError(t, backend.Put(ctx, "s", "key", []byte("value"), time.Microsecond))
	require.Equal(t, time.Millisecond, server.TTL("session:{s}:key"))

	require.NoError(t, backend.Revoke(ctx, "other", time.Microsecond))
	require.Equal(t, time.Millisecond, server.TTL("session:{other}#revoked"))
}

type operation struct {
	name string
	call func(sessionID string) error
}

// operations lists every Backend method as a call on sessionID.
func operations(t *testing.T, backend *redisbackend.Backend) []operation {
	t.Helper()
	ctx := t.Context()
	return []operation{
		{name: "put", call: func(sessionID string) error {
			return backend.Put(ctx, sessionID, "key", []byte("value"), time.Hour)
		}},
		{name: "get", call: func(sessionID string) error { _, _, err := backend.Get(ctx, sessionID, "key"); return err }},
		{name: "pop", call: func(sessionID string) error { _, _, err := backend.Pop(ctx, sessionID, "key"); return err }},
		{name: "revoke", call: func(sessionID string) error { return backend.Revoke(ctx, sessionID, time.Hour) }},
	}
}

// A session ID that would split the keys of a session across cluster slots is refused before any I/O.
func TestInvalidSessionIDIsRefused(t *testing.T) {
	backend, server := newBackend(t, "")
	invalidIDs := []string{"", "{", "}", "{}", "}abc{", "abc{def", "abc}def"}
	for _, operation := range operations(t, backend) {
		t.Run(operation.name, func(t *testing.T) {
			for _, sessionID := range invalidIDs {
				err := operation.call(sessionID)

				require.ErrorContains(t, err, "session ID must be non-empty", "%q", sessionID)
				require.NotErrorIs(t, err, session.ErrSessionRevoked, "%q", sessionID)
				require.NotContains(t, err.Error(), "abc", "the ID stays out of the message")
			}
			require.Empty(t, server.Keys(), "a refused call writes nothing")
		})
	}
}

// A connection failure is an error, never "not found", and carries no go-redis error chain (LIB-010).
func TestConnectionFailureSurfacesAsError(t *testing.T) {
	server, client := newRedis(t)
	backend, err := redisbackend.New(&redisbackend.Options{Client: client})
	require.NoError(t, err)
	server.Close()

	for _, operation := range operations(t, backend) {
		t.Run(operation.name, func(t *testing.T) {
			err := operation.call("s")

			require.Error(t, err)
			require.ErrorContains(t, err, "redis session backend")
			require.NotErrorIs(t, err, redis.Nil)
			require.NotErrorIs(t, err, session.ErrSessionRevoked)
			require.NoError(t, errors.Unwrap(err), "the go-redis chain is dropped")
		})
	}
}
