// Package backendtest is the conformance suite every session.Backend implementation of the module runs
// in its tests: put, get, pop, compare and swap, revoke, per-value TTLs, revocation markers, atomic Pop
// and CompareAndSwap, and revocation racing a Put. Use it from tests only.
package backendtest

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/session"
)

const raceRounds = 50

// roundMessage names the race round in a failed assertion.
const roundMessage = "round %d"

// Run exercises every session.Backend contract (put/get/pop/compare-and-swap/revoke, TTL, atomic pop and swap
// under -race, revoke marker vs put).
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
		{name: "compare and swap replaces only the expected value", run: testCompareAndSwap},
		{name: "revoke deletes the session and refuses puts", run: testRevoke},
		{name: "values expire after their ttl", run: testExpiry},
		{name: "revoke reaches values outliving shorter ones", run: testRevokeAfterMixedTTLs},
		{name: "revocation marker expires after its ttl", run: testMarkerExpiry},
		{name: "revocation marker never outlives the revoked values", run: testMarkerLifetimeFollowsTheValues},
		{name: "revocation marker ignores replaced and popped values", run: testMarkerLifetimeFollowsTheLiveValues},
		{name: "concurrent pops find the value once", run: testConcurrentPop},
		{name: "concurrent swaps of one value succeed once", run: testConcurrentCompareAndSwap},
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

func testCompareAndSwap(t *testing.T, backend session.Backend, advance func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s", "key", []byte("v1"), time.Hour))

	require.False(t, swap(t, backend, "s", "other", "v2"))
	requireValue(t, backend, "s", "key", "v1")
	require.True(t, swap(t, backend, "s", "v1", "v2"))
	requireValue(t, backend, "s", "key", "v2")
	require.False(t, swap(t, backend, "missing", "", "v1"))
	requireAbsent(t, backend, "missing", "key")

	require.NoError(t, backend.Put(ctx, "short", "key", []byte("v1"), time.Minute))
	advance(30 * time.Second)
	require.True(t, swap(t, backend, "short", "v1", "v2"))
	advance(30*time.Second + time.Second)
	requireAbsent(t, backend, "short", "key")
	require.False(t, swap(t, backend, "short", "v2", "v3"))
	requireAbsent(t, backend, "short", "key")

	require.NoError(t, backend.Revoke(ctx, "s", time.Hour))
	require.False(t, swap(t, backend, "s", "v2", "v3"))
	requireAbsent(t, backend, "s", "key")
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
	require.ErrorIs(t, backend.Put(ctx, "s1", "a", []byte("1"), time.Hour), session.ErrRevoked)
	requireAbsent(t, backend, "s1", "a")
	requireValue(t, backend, "s2", "a", "other")

	require.NoError(t, backend.Revoke(ctx, "s1", time.Hour), "revoking twice")
	require.ErrorIs(t, backend.Put(ctx, "s1", "a", []byte("1"), time.Hour), session.ErrRevoked, "revoking twice keeps the marker")

	require.NoError(t, backend.Revoke(ctx, "never-used", time.Hour))
	require.NoError(t, backend.Put(ctx, "never-used", "a", []byte("1"), time.Hour), "an ID without values gets no marker")
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
	require.NoError(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour))
	require.NoError(t, backend.Revoke(ctx, "s", time.Minute))

	advance(time.Minute - time.Second)
	require.ErrorIs(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour), session.ErrRevoked)

	advance(2 * time.Second)
	require.NoError(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour))
	requireValue(t, backend, "s", "key", "value")
}

// testMarkerLifetimeFollowsTheValues: a marker replaces the session's values and lives no longer than the
// latest of them would have, so revoking never makes a session hold its slot longer.
func testMarkerLifetimeFollowsTheValues(t *testing.T, backend session.Backend, advance func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "s", "short", []byte("value"), time.Minute))
	require.NoError(t, backend.Put(ctx, "s", "long", []byte("value"), 10*time.Minute))
	require.NoError(t, backend.Revoke(ctx, "s", time.Hour))

	advance(10*time.Minute - time.Second)
	require.ErrorIs(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour), session.ErrRevoked)

	advance(2 * time.Second)
	require.NoError(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour))
}

// testMarkerLifetimeFollowsTheLiveValues: the marker follows the values a session holds when it is revoked,
// not a longer-lived value replaced or popped before.
func testMarkerLifetimeFollowsTheLiveValues(t *testing.T, backend session.Backend, advance func(time.Duration)) {
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "replaced", "key", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "replaced", "key", []byte("value"), time.Minute))
	require.NoError(t, backend.Put(ctx, "popped", "long", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "popped", "short", []byte("value"), 10*time.Minute))
	_, _, err := backend.Pop(ctx, "popped", "long")
	require.NoError(t, err)
	advance(2 * time.Minute)

	require.NoError(t, backend.Revoke(ctx, "replaced", 24*time.Hour))
	require.NoError(t, backend.Revoke(ctx, "popped", 24*time.Hour))

	require.NoError(t, backend.Put(ctx, "replaced", "key", []byte("value"), time.Hour), "its value had expired: no marker")
	advance(8*time.Minute - time.Second)
	require.ErrorIs(t, backend.Put(ctx, "popped", "key", []byte("value"), time.Hour), session.ErrRevoked)
	advance(2 * time.Second)
	require.NoError(t, backend.Put(ctx, "popped", "key", []byte("value"), time.Hour), "the marker lived as long as the value left")
}

func testConcurrentPop(t *testing.T, backend session.Backend, _ func(time.Duration)) {
	ctx := t.Context()
	type popResult struct {
		value []byte
		found bool
		err   error
	}
	for round := range raceRounds {
		require.NoError(t, backend.Put(ctx, "s", "state", []byte("value"), time.Hour))
		results := make([]popResult, 8)
		var waitGroup sync.WaitGroup
		for index := range results {
			waitGroup.Go(func() {
				value, found, err := backend.Pop(ctx, "s", "state")
				results[index] = popResult{value: value, found: found, err: err}
			})
		}
		waitGroup.Wait()

		winners := 0
		for _, result := range results {
			require.NoError(t, result.err, roundMessage, round)
			if result.found {
				winners++
				require.Equal(t, "value", string(result.value), roundMessage, round)
			}
		}
		require.Equal(t, 1, winners, roundMessage, round)
		requireAbsent(t, backend, "s", "state")
	}
}

func testConcurrentCompareAndSwap(t *testing.T, backend session.Backend, _ func(time.Duration)) {
	ctx := t.Context()
	for round := range raceRounds {
		require.NoError(t, backend.Put(ctx, "s", "identity", []byte("read"), time.Hour))
		swapped := make([]bool, 8)
		swapErrors := make([]error, 8)
		var waitGroup sync.WaitGroup
		for index := range swapped {
			waitGroup.Go(func() {
				swapped[index], swapErrors[index] = backend.CompareAndSwap(ctx, "s", "identity", []byte("read"), fmt.Appendf(nil, "writer-%d", index))
			})
		}
		waitGroup.Wait()

		winner := -1
		for index := range swapped {
			require.NoError(t, swapErrors[index], roundMessage, round)
			if swapped[index] {
				require.Equal(t, -1, winner, "round %d: two swaps of one value", round)
				winner = index
			}
		}
		require.NotEqual(t, -1, winner, "round %d: no swap", round)
		requireValue(t, backend, "s", "identity", fmt.Sprintf("writer-%d", winner))
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

		require.NoError(t, revokeError, roundMessage, round)
		if putError != nil {
			require.ErrorIs(t, putError, session.ErrRevoked, roundMessage, round)
		}
		requireAbsent(t, backend, sessionID, "a")
		requireAbsent(t, backend, sessionID, "b")
		require.ErrorIs(t, backend.Put(ctx, sessionID, "c", []byte("3"), time.Hour), session.ErrRevoked, roundMessage, round)
	}
}

func requireValue(t *testing.T, backend session.Backend, sessionID, key, want string) {
	t.Helper()
	value, found, err := backend.Get(t.Context(), sessionID, key)
	require.NoError(t, err)
	require.True(t, found, "%s/%s is absent", sessionID, key)
	require.Equal(t, want, string(value))
}

// swap swaps previous for value under (sessionID, "key") and reports whether that happened.
func swap(t *testing.T, backend session.Backend, sessionID, previous, value string) bool {
	t.Helper()
	swapped, err := backend.CompareAndSwap(t.Context(), sessionID, "key", []byte(previous), []byte(value))
	require.NoError(t, err)
	return swapped
}

func requireAbsent(t *testing.T, backend session.Backend, sessionID, key string) {
	t.Helper()
	_, found, err := backend.Get(t.Context(), sessionID, key)
	require.NoError(t, err)
	require.False(t, found, "%s/%s is present", sessionID, key)
}
