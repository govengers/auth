// Package backendtest is the conformance suite every session.Backend implementation of the module runs
// in its tests: put, get, pop, revoke, per-value TTLs, revocation markers, atomic Pop and revocation
// racing a Put. Use it from tests only.
package backendtest

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/session"
)

const raceRounds = 50

// Run exercises every session.Backend contract (put/get/pop/revoke, TTL, atomic pop under -race, revoke marker vs put).
// newBackend returns a fresh, empty backend for one subtest and the function that moves that backend's
// clock forward (miniredis: FastForward; the memory backend: its test clock).
func Run(t *testing.T, newBackend func(t *testing.T) (session.Backend, func(duration time.Duration))) {
	t.Helper()
	testCases := []struct {
		name string
		run  func(t *testing.T, backend session.Backend, advance func(time.Duration))
	}{
		{name: "put replaces and get reads", run: testPutAndGet},
		{name: "values are copied", run: testValuesAreCopied},
		{name: "pop takes the value once", run: testPop},
		{name: "revoke deletes the session and refuses puts", run: testRevoke},
		{name: "values expire after their ttl", run: testExpiry},
		{name: "revoke reaches values outliving shorter ones", run: testRevokeAfterMixedTTLs},
		{name: "revocation marker expires after its ttl", run: testMarkerExpiry},
		{name: "concurrent pops find the value once", run: testConcurrentPop},
		{name: "revoke racing a put leaves nothing", run: testRevokeRacingPut},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend, advance := newBackend(t)
			testCase.run(t, backend, advance)
		})
	}
}

func testPutAndGet(t *testing.T, backend session.Backend, _ func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s1", "key", []byte("v1"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s1", "key", []byte("v2"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s2", "key", []byte("other"), time.Hour))

	requireValue(t, backend, "s1", "key", "v2")
	requireValue(t, backend, "s2", "key", "other")
	requireAbsent(t, backend, "s1", "missing")
	requireAbsent(t, backend, "unknown", "key")
}

func testValuesAreCopied(t *testing.T, backend session.Backend, _ func(time.Duration)) {
	ctx := t.Context()
	value := []byte("value")
	require.NoError(t, backend.Put(ctx, "s", "key", value, time.Hour))
	value[0] = 'X'

	read, found, err := backend.Get(ctx, "s", "key")
	require.NoError(t, err)
	require.True(t, found)
	read[0] = 'Y'

	requireValue(t, backend, "s", "key", "value")
}

func testPop(t *testing.T, backend session.Backend, _ func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s", "other", []byte("kept"), time.Hour))

	value, found, err := backend.Pop(ctx, "s", "key")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "value", string(value))

	_, found, err = backend.Pop(ctx, "s", "key")
	require.NoError(t, err)
	require.False(t, found)
	requireAbsent(t, backend, "s", "key")
	requireValue(t, backend, "s", "other", "kept")
}

func testRevoke(t *testing.T, backend session.Backend, _ func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s1", "a", []byte("1"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s1", "b", []byte("2"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s2", "a", []byte("other"), time.Hour))

	require.NoError(t, backend.Revoke(ctx, "s1", time.Hour))

	requireAbsent(t, backend, "s1", "a")
	_, found, err := backend.Pop(ctx, "s1", "b")
	require.NoError(t, err)
	require.False(t, found)
	require.ErrorIs(t, backend.Put(ctx, "s1", "a", []byte("1"), time.Hour), session.ErrSessionRevoked)
	requireAbsent(t, backend, "s1", "a")
	requireValue(t, backend, "s2", "a", "other")

	require.NoError(t, backend.Revoke(ctx, "never-used", time.Hour))
	require.ErrorIs(t, backend.Put(ctx, "never-used", "a", []byte("1"), time.Hour), session.ErrSessionRevoked)
	require.NoError(t, backend.Revoke(ctx, "s1", time.Hour), "revoking twice")
}

func testExpiry(t *testing.T, backend session.Backend, advance func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s", "get", []byte("value"), time.Minute))
	require.NoError(t, backend.Put(ctx, "s", "pop", []byte("value"), time.Minute))

	advance(time.Minute - time.Second)
	requireValue(t, backend, "s", "get", "value")

	advance(2 * time.Second)
	requireAbsent(t, backend, "s", "get")
	_, found, err := backend.Pop(ctx, "s", "pop")
	require.NoError(t, err)
	require.False(t, found)
}

func testRevokeAfterMixedTTLs(t *testing.T, backend session.Backend, advance func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s", "long", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "s", "short", []byte("value"), time.Minute))

	advance(2 * time.Minute)
	requireAbsent(t, backend, "s", "short")
	requireValue(t, backend, "s", "long", "value")

	require.NoError(t, backend.Revoke(ctx, "s", time.Hour))
	requireAbsent(t, backend, "s", "long")
}

func testMarkerExpiry(t *testing.T, backend session.Backend, advance func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Revoke(ctx, "s", time.Minute))

	advance(time.Minute - time.Second)
	require.ErrorIs(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour), session.ErrSessionRevoked)

	advance(2 * time.Second)
	require.NoError(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour))
	requireValue(t, backend, "s", "key", "value")
}

func testConcurrentPop(t *testing.T, backend session.Backend, _ func(time.Duration)) {
	ctx := t.Context()
	for round := range raceRounds {
		require.NoError(t, backend.Put(ctx, "s", "state", []byte("value"), time.Hour))
		var winners atomic.Int32
		var waitGroup sync.WaitGroup
		for range 8 {
			waitGroup.Go(func() {
				_, found, err := backend.Pop(ctx, "s", "state")
				if err == nil && found {
					winners.Add(1)
				}
			})
		}
		waitGroup.Wait()
		require.Equal(t, int32(1), winners.Load(), "round %d", round)
	}
}

// testRevokeRacingPut: whatever the interleaving, once both are done the session holds nothing and
// refuses further puts. A put either lands first and is revoked with the rest, or is refused.
func testRevokeRacingPut(t *testing.T, backend session.Backend, _ func(time.Duration)) {
	ctx := t.Context()
	for round := range raceRounds {
		sessionID := fmt.Sprintf("session-%d", round)
		require.NoError(t, backend.Put(ctx, sessionID, "a", []byte("1"), time.Hour))
		var putError, revokeError error
		var waitGroup sync.WaitGroup
		waitGroup.Go(func() { putError = backend.Put(ctx, sessionID, "b", []byte("2"), time.Hour) })
		waitGroup.Go(func() { revokeError = backend.Revoke(ctx, sessionID, time.Hour) })
		waitGroup.Wait()

		require.NoError(t, revokeError, "round %d", round)
		if putError != nil {
			require.ErrorIs(t, putError, session.ErrSessionRevoked, "round %d", round)
		}
		requireAbsent(t, backend, sessionID, "a")
		requireAbsent(t, backend, sessionID, "b")
		require.ErrorIs(t, backend.Put(ctx, sessionID, "c", []byte("3"), time.Hour), session.ErrSessionRevoked, "round %d", round)
	}
}

func requireValue(t *testing.T, backend session.Backend, sessionID, key, want string) {
	t.Helper()
	value, found, err := backend.Get(t.Context(), sessionID, key)
	require.NoError(t, err)
	require.True(t, found, "%s/%s is absent", sessionID, key)
	require.Equal(t, want, string(value))
}

func requireAbsent(t *testing.T, backend session.Backend, sessionID, key string) {
	t.Helper()
	_, found, err := backend.Get(t.Context(), sessionID, key)
	require.NoError(t, err)
	require.False(t, found, "%s/%s is present", sessionID, key)
}
