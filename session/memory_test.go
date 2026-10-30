package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMemoryBackend(t *testing.T) {
	testCases := []struct {
		name             string
		options          *MemoryBackendOptions
		wantMaximum      int
		wantMaximumBytes int
		wantError        string
	}{
		{name: "nil options take defaults", options: nil, wantMaximum: 100000, wantMaximumBytes: 64 << 20},
		{name: "zero takes the default", options: &MemoryBackendOptions{}, wantMaximum: 100000, wantMaximumBytes: 64 << 20},
		{name: "explicit maximums", options: &MemoryBackendOptions{MaximumSessions: 3, MaximumBytes: 1024}, wantMaximum: 3, wantMaximumBytes: 1024},
		{name: "negative maximum", options: &MemoryBackendOptions{MaximumSessions: -1}, wantError: "MaximumSessions -1 is negative"},
		{name: "negative maximum bytes", options: &MemoryBackendOptions{MaximumBytes: -1}, wantError: "MaximumBytes -1 is negative"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var original MemoryBackendOptions
			if testCase.options != nil {
				original = *testCase.options
			}

			backend, err := NewMemoryBackend(testCase.options)

			if testCase.wantError != "" {
				require.ErrorContains(t, err, testCase.wantError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.wantMaximum, backend.options.MaximumSessions)
			require.Equal(t, testCase.wantMaximumBytes, backend.options.MaximumBytes)
			if testCase.options != nil {
				require.Equal(t, original, *testCase.options, "caller's options untouched")
			}
		})
	}
}

func TestMemoryBackendEviction(t *testing.T) {
	testCases := []struct {
		name        string
		fill        func(t *testing.T, backend *MemoryBackend, clock *testClock)
		wantEvicted string
		wantKept    []string
	}{
		{
			name: "evicts the session expiring soonest",
			fill: func(t *testing.T, backend *MemoryBackend, _ *testClock) {
				require.NoError(t, backend.Put(t.Context(), "late", "key", []byte("value"), 2*time.Hour))
				require.NoError(t, backend.Put(t.Context(), "soon", "key", []byte("value"), time.Hour))
			},
			wantEvicted: "soon",
			wantKept:    []string{"late"},
		},
		{
			name: "a session expires with its last value",
			fill: func(t *testing.T, backend *MemoryBackend, _ *testClock) {
				require.NoError(t, backend.Put(t.Context(), "mixed", "short", []byte("value"), time.Minute))
				require.NoError(t, backend.Put(t.Context(), "mixed", "long", []byte("value"), 3*time.Hour))
				require.NoError(t, backend.Put(t.Context(), "single", "key", []byte("value"), 2*time.Hour))
			},
			wantEvicted: "single",
			wantKept:    []string{"mixed"},
		},
		{
			name: "evicts the session expiring soonest, not a revoked one expiring later",
			fill: func(t *testing.T, backend *MemoryBackend, _ *testClock) {
				require.NoError(t, backend.Put(t.Context(), "revoked", "key", []byte("value"), 2*time.Hour))
				require.NoError(t, backend.Revoke(t.Context(), "revoked", 24*time.Hour))
				require.NoError(t, backend.Put(t.Context(), "soon", "key", []byte("value"), time.Hour))
			},
			wantEvicted: "soon",
			wantKept:    []string{"revoked"},
		},
		{
			name: "evicts a revocation marker expiring soonest",
			fill: func(t *testing.T, backend *MemoryBackend, _ *testClock) {
				require.NoError(t, backend.Put(t.Context(), "late", "key", []byte("value"), 2*time.Hour))
				require.NoError(t, backend.Put(t.Context(), "revoked", "key", []byte("value"), time.Hour))
				require.NoError(t, backend.Revoke(t.Context(), "revoked", 24*time.Hour))
			},
			wantEvicted: "revoked",
			wantKept:    []string{"late"},
		},
		{
			name: "drops expired sessions before evicting live ones",
			fill: func(t *testing.T, backend *MemoryBackend, clock *testClock) {
				require.NoError(t, backend.Put(t.Context(), "expired", "key", []byte("value"), time.Minute))
				require.NoError(t, backend.Put(t.Context(), "live", "key", []byte("value"), time.Hour))
				clock.advance(2 * time.Minute)
			},
			wantEvicted: "expired",
			wantKept:    []string{"live"},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			clock := newTestClock()
			backend, err := NewMemoryBackend(&MemoryBackendOptions{MaximumSessions: 2})
			require.NoError(t, err)
			backend.now = clock.now
			testCase.fill(t, backend, clock)

			require.NoError(t, backend.Put(t.Context(), "new", "key", []byte("value"), time.Hour))

			require.Len(t, backend.sessions, 2)
			require.NotContains(t, backend.sessions, testCase.wantEvicted)
			for _, sessionID := range append(testCase.wantKept, "new") {
				require.Contains(t, backend.sessions, sessionID)
			}
		})
	}
}

// recountedBytes is what storedBytes must be: every session ID, key and value held.
func recountedBytes(backend *MemoryBackend) int {
	total := 0
	for sessionID, entry := range backend.sessions {
		total += len(sessionID)
		for key, item := range entry.values {
			total += len(key) + len(item.value)
		}
	}
	return total
}

func TestMemoryBackendByteBudget(t *testing.T) {
	value := bytes.Repeat([]byte("v"), 40) // 47 bytes with a 4-byte session ID and the key "key"
	testCases := []struct {
		name        string
		fill        func(t *testing.T, backend *MemoryBackend, clock *testClock)
		write       func(t *testing.T, backend *MemoryBackend) error
		wantError   string
		wantEvicted []string
		wantKept    []string
	}{
		{
			name: "evicts the session expiring soonest",
			fill: func(t *testing.T, backend *MemoryBackend, _ *testClock) {
				require.NoError(t, backend.Put(t.Context(), "late", "key", value, 2*time.Hour))
				require.NoError(t, backend.Put(t.Context(), "soon", "key", value, time.Hour))
			},
			write: func(t *testing.T, backend *MemoryBackend) error {
				return backend.Put(t.Context(), "news", "key", value, 3*time.Hour)
			},
			wantEvicted: []string{"soon"}, wantKept: []string{"late", "news"},
		},
		{
			name: "drops expired entries before evicting live ones",
			fill: func(t *testing.T, backend *MemoryBackend, clock *testClock) {
				small := value[:20] // 27 bytes per session
				require.NoError(t, backend.Put(t.Context(), "gon1", "key", small, time.Minute))
				require.NoError(t, backend.Put(t.Context(), "gon2", "key", small, 2*time.Minute))
				require.NoError(t, backend.Put(t.Context(), "live", "key", small, time.Hour))
				clock.advance(3 * time.Minute)
			},
			write: func(t *testing.T, backend *MemoryBackend) error {
				return backend.Put(t.Context(), "news", "key", value[:20], 30*time.Minute)
			},
			wantEvicted: []string{"gon1", "gon2"}, wantKept: []string{"live", "news"},
		},
		{
			name: "a growing swap makes room",
			fill: func(t *testing.T, backend *MemoryBackend, _ *testClock) {
				require.NoError(t, backend.Put(t.Context(), "soon", "key", value, time.Hour))
				require.NoError(t, backend.Put(t.Context(), "late", "key", []byte("v"), 2*time.Hour))
			},
			write: func(t *testing.T, backend *MemoryBackend) error {
				swapped, err := backend.CompareAndSwap(t.Context(), "late", "key", []byte("v"), bytes.Repeat([]byte("v"), 60))
				require.True(t, swapped)
				return err
			},
			wantEvicted: []string{"soon"}, wantKept: []string{"late"},
		},
		{
			name: "a session evicted for its own write comes back within the budget",
			fill: func(t *testing.T, backend *MemoryBackend, _ *testClock) {
				require.NoError(t, backend.Put(t.Context(), "o", "k", bytes.Repeat([]byte("o"), 60), 2*time.Hour))        // 62 bytes
				require.NoError(t, backend.Put(t.Context(), "ssssssssss", "a", bytes.Repeat([]byte("a"), 10), time.Hour)) // 21, expires first
			},
			write: func(t *testing.T, backend *MemoryBackend) error {
				return backend.Put(t.Context(), "ssssssssss", "b", bytes.Repeat([]byte("b"), 30), time.Hour) // 31 more, 41 as a new session
			},
			wantEvicted: []string{"o"}, wantKept: []string{"ssssssssss"},
		},
		{
			name: "a value that cannot fit is refused and evicts nothing",
			fill: func(t *testing.T, backend *MemoryBackend, _ *testClock) {
				require.NoError(t, backend.Put(t.Context(), "live", "key", value, time.Hour))
			},
			write: func(t *testing.T, backend *MemoryBackend) error {
				return backend.Put(t.Context(), "news", "key", bytes.Repeat([]byte("v"), 100), time.Hour)
			},
			wantError: "cannot fit in MaximumBytes 100", wantKept: []string{"live"},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			clock := newTestClock()
			backend, err := NewMemoryBackend(&MemoryBackendOptions{MaximumBytes: 100})
			require.NoError(t, err)
			backend.now = clock.now
			testCase.fill(t, backend, clock)

			err = testCase.write(t, backend)

			if testCase.wantError != "" {
				require.ErrorContains(t, err, testCase.wantError)
			} else {
				require.NoError(t, err)
			}
			for _, sessionID := range testCase.wantEvicted {
				require.NotContains(t, backend.sessions, sessionID)
			}
			for _, sessionID := range testCase.wantKept {
				require.Contains(t, backend.sessions, sessionID)
			}
			require.Equal(t, recountedBytes(backend), backend.storedBytes)
			require.LessOrEqual(t, backend.storedBytes, 100)
		})
	}
}

func TestMemoryBackendBudgetsOnlyTheNetGrowthOfAReplacement(t *testing.T) {
	testCases := []struct {
		name  string
		token []byte
	}{
		{name: "same size", token: bytes.Repeat([]byte("n"), 21)},
		{name: "shrinking", token: []byte("short")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend, err := NewMemoryBackend(&MemoryBackendOptions{MaximumBytes: 100})
			require.NoError(t, err)
			backend.now = newTestClock().now
			ctx := t.Context()
			require.NoError(t, backend.Put(ctx, "s", "identity", bytes.Repeat([]byte("i"), 40), time.Hour)) // 49 bytes
			require.NoError(t, backend.Put(ctx, "s", "token", bytes.Repeat([]byte("t"), 21), time.Hour))    // 75
			require.NoError(t, backend.Put(ctx, "o", "k", bytes.Repeat([]byte("o"), 20), 2*time.Hour))      // 97

			require.NoError(t, backend.Put(ctx, "s", "token", testCase.token, time.Hour))

			for _, stored := range []struct{ sessionID, key string }{{"s", "identity"}, {"s", "token"}, {"o", "k"}} {
				_, found, err := backend.Get(ctx, stored.sessionID, stored.key)
				require.NoError(t, err)
				require.True(t, found, "%s/%s survives a replacement that fits", stored.sessionID, stored.key)
			}
			require.Equal(t, recountedBytes(backend), backend.storedBytes)
		})
	}
}

func TestMemoryBackendCountsBytesThroughEveryOperation(t *testing.T) {
	clock := newTestClock()
	backend := newTestMemoryBackend(t, clock)
	ctx := t.Context()

	require.NoError(t, backend.Put(ctx, "first", "a", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "first", "a", []byte("longer value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "first", "b", []byte("value"), time.Hour))
	_, err := backend.CompareAndSwap(ctx, "first", "b", []byte("value"), []byte("v"))
	require.NoError(t, err)
	require.NoError(t, backend.Put(ctx, "second", "a", []byte("value"), time.Hour))
	_, _, err = backend.Pop(ctx, "second", "a")
	require.NoError(t, err)
	require.NoError(t, backend.Revoke(ctx, "first", time.Hour))

	require.Equal(t, recountedBytes(backend), backend.storedBytes)
	require.Equal(t, len("first"), backend.storedBytes, "only the revocation marker is left")
}

func TestMemoryBackendRevokeTakesNoSlot(t *testing.T) {
	backend, err := NewMemoryBackend(&MemoryBackendOptions{MaximumSessions: 2})
	require.NoError(t, err)
	backend.now = newTestClock().now
	require.NoError(t, backend.Put(t.Context(), "first", "key", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(t.Context(), "second", "key", []byte("value"), 2*time.Hour))

	require.NoError(t, backend.Revoke(t.Context(), "first", 24*time.Hour))
	require.NoError(t, backend.Revoke(t.Context(), "never-used", 24*time.Hour))

	require.Len(t, backend.sessions, 2)
	require.Contains(t, backend.sessions, "second")
	require.NotContains(t, backend.sessions, "never-used")
}

func TestMemoryBackendRevokeOfExpiredValuesLeavesNothing(t *testing.T) {
	clock := newTestClock()
	backend := newTestMemoryBackend(t, clock)
	require.NoError(t, backend.Put(t.Context(), "session", "key", []byte("value"), time.Minute))
	clock.advance(2 * time.Minute)

	require.NoError(t, backend.Revoke(t.Context(), "session", time.Hour))

	require.Empty(t, backend.sessions)
}

func TestMemoryBackendDropsEmptiedSessions(t *testing.T) {
	clock := newTestClock()
	backend := newTestMemoryBackend(t, clock)
	require.NoError(t, backend.Put(t.Context(), "session", "key", []byte("value"), time.Hour))

	_, found, err := backend.Pop(t.Context(), "session", "key")

	require.NoError(t, err)
	require.True(t, found)
	require.Empty(t, backend.sessions)
}
