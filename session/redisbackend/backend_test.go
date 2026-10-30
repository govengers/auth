package redisbackend_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
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
	return newRedisOn(t, miniredis.RunT(t))
}

// newRedisOn returns a client on server without retries; the client is closed with the test.
func newRedisOn(t *testing.T, server *miniredis.Miniredis) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1, DialerRetries: 1})
	t.Cleanup(func() { _ = client.Close() }) // nothing to flush
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
		name      string
		options   *redisbackend.Options
		wantError string
	}{
		{name: "nil options", options: nil, wantError: "options are required"},
		{name: "missing client", options: &redisbackend.Options{}, wantError: "Client is required"},
		{name: "opening brace in prefix", options: &redisbackend.Options{Client: client, KeyPrefix: "a{b"}, wantError: "must not contain"},
		{name: "closing brace in prefix", options: &redisbackend.Options{Client: client, KeyPrefix: "a}b"}, wantError: "must not contain"},
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

			if testCase.wantError != "" {
				require.ErrorContains(t, err, testCase.wantError)
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
	require.NoError(t, backend.Put(ctx, "s3", "a", []byte("4"), time.Hour))
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
	require.NoError(t, backend.Put(ctx, "s1", "key", []byte("value"), time.Hour))
	require.NoError(t, backend.Revoke(ctx, "s1", time.Hour))

	err := backend.Put(ctx, "s1", "key", []byte("value"), time.Hour)

	require.ErrorIs(t, err, session.ErrRevoked)
	require.False(t, server.Exists("session:{s1}:key"), "a refused put writes nothing")
	require.False(t, server.Exists("session:{s1}"), "a refused put indexes nothing")
}

func TestRevokeStoresNothingForAnUnknownSession(t *testing.T) {
	backend, server := newBackend(t, "")

	require.NoError(t, backend.Revoke(t.Context(), "never-used", time.Hour))

	require.Empty(t, server.Keys())
}

func TestRevocationMarkerLivesAsLongAsTheRevokedValues(t *testing.T) {
	backend, server := newBackend(t, "")
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s", "state", []byte("value"), 10*time.Minute))

	require.NoError(t, backend.Revoke(ctx, "s", 24*time.Hour))

	require.Equal(t, 10*time.Minute, server.TTL("session:{s}#revoked"))
}

// go-redis retries a command whose reply was lost (MaxRetries defaults to 3). The retried Pop must return
// the value the lost attempt consumed, not report it absent, and must not consume a value written between
// the lost attempt and the retry.
func TestPopSurvivesARetryAfterALostReply(t *testing.T) {
	server := miniredis.RunT(t)
	_, otherClient := newRedisOn(t, server)
	other, err := redisbackend.New(&redisbackend.Options{Client: otherClient})
	require.NoError(t, err)
	ctx := t.Context()
	var replacementError error
	backend, dropReply := newReplyDroppingBackend(t, server, func() {
		replacementError = other.Put(t.Context(), "s", "state", []byte("replacement"), time.Hour)
	})
	require.NoError(t, backend.Put(ctx, "s", "state", []byte("value"), time.Hour))
	_, _, err = backend.Pop(ctx, "s", "warm-up") // loads the script, so the next Pop runs on its first EVALSHA
	require.NoError(t, err)

	dropReply.Store(true)
	value, found, err := backend.Pop(ctx, "s", "state")

	require.False(t, dropReply.Load(), "a reply was dropped")
	require.NoError(t, replacementError)
	require.NoError(t, err)
	require.True(t, found, "the retry returns what the lost attempt consumed")
	require.Equal(t, "value", string(value))
	value, found, err = backend.Get(ctx, "s", "state")
	require.NoError(t, err)
	require.True(t, found, "the retry left the value written after the lost attempt")
	require.Equal(t, "replacement", string(value))
}

// The retried CompareAndSwap must report the swap the lost attempt made, even when another client changed
// the value before the retry: a clean false would tell the Guard it lost its refresh claim.
func TestCompareAndSwapSurvivesARetryAfterALostReply(t *testing.T) {
	server := miniredis.RunT(t)
	_, otherClient := newRedisOn(t, server)
	other, err := redisbackend.New(&redisbackend.Options{Client: otherClient})
	require.NoError(t, err)
	ctx := t.Context()
	var otherError error
	backend, dropReply := newReplyDroppingBackend(t, server, func() {
		_, otherError = other.CompareAndSwap(t.Context(), "s", "identity", []byte("claimed"), []byte("saved"))
	})
	require.NoError(t, backend.Put(ctx, "s", "identity", []byte("read"), time.Hour))
	_, err = backend.CompareAndSwap(ctx, "s", "warm-up", nil, nil) // loads the script
	require.NoError(t, err)

	dropReply.Store(true)
	swapped, err := backend.CompareAndSwap(ctx, "s", "identity", []byte("read"), []byte("claimed"))

	require.False(t, dropReply.Load(), "a reply was dropped")
	require.NoError(t, otherError)
	require.NoError(t, err)
	require.True(t, swapped, "the retry reports the swap the lost attempt made")
	value, found, err := backend.Get(ctx, "s", "identity")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "saved", string(value), "the retry left the value swapped in after the lost attempt")
}

// newReplyDroppingBackend returns a backend on server with go-redis's default retries whose connection loses
// the reply to the next script call once dropReply is set; onDrop runs before the client retries.
func newReplyDroppingBackend(t *testing.T, server *miniredis.Miniredis, onDrop func()) (*redisbackend.Backend, *atomic.Bool) {
	t.Helper()
	dropReply := &atomic.Bool{}
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &replyDroppingConnection{Conn: connection, dropReply: dropReply, onDrop: onDrop}, nil
	}})
	t.Cleanup(func() { _ = client.Close() }) // nothing to flush
	backend, err := redisbackend.New(&redisbackend.Options{Client: client})
	require.NoError(t, err)
	return backend, dropReply
}

// replyDroppingConnection loses the reply to the next script call once dropReply is set: the server ran the
// script, the client sees the connection end, as when the network drops a response. onDrop runs between the
// lost reply and the client's retry.
type replyDroppingConnection struct {
	net.Conn
	dropReply *atomic.Bool
	onDrop    func()
	dropping  bool
}

func (c *replyDroppingConnection) Write(data []byte) (int, error) {
	if bytes.Contains(bytes.ToLower(data), []byte("evalsha")) && c.dropReply.CompareAndSwap(true, false) {
		c.dropping = true
	}
	return c.Conn.Write(data)
}

func (c *replyDroppingConnection) Read(buffer []byte) (int, error) {
	if c.dropping {
		c.dropping = false
		_, _ = c.Conn.Read(buffer) // the reply arrived: the script ran
		_ = c.Close()              // the reply is lost on purpose; nothing to flush
		c.onDrop()
		return 0, io.EOF
	}
	return c.Conn.Read(buffer)
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

	require.NoError(t, backend.Put(ctx, "other", "key", []byte("value"), time.Hour))
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
		{name: "compare and swap", call: func(sessionID string) error {
			_, err := backend.CompareAndSwap(ctx, sessionID, "key", []byte("previous"), []byte("value"))
			return err
		}},
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
				require.NotErrorIs(t, err, session.ErrRevoked, "%q", sessionID)
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
			require.NotErrorIs(t, err, session.ErrRevoked)
			require.NoError(t, errors.Unwrap(err), "the go-redis chain is dropped")
		})
	}
}
