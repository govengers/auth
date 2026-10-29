package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMemoryBackend(t *testing.T) {
	testCases := []struct {
		name        string
		options     *MemoryBackendOptions
		wantMaximum int
		wantErr     string
	}{
		{name: "nil options take defaults", options: nil, wantMaximum: 100000},
		{name: "zero takes the default", options: &MemoryBackendOptions{}, wantMaximum: 100000},
		{name: "explicit maximum", options: &MemoryBackendOptions{MaximumSessions: 3}, wantMaximum: 3},
		{name: "negative maximum", options: &MemoryBackendOptions{MaximumSessions: -1}, wantErr: "MaximumSessions -1 is negative"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var original MemoryBackendOptions
			if testCase.options != nil {
				original = *testCase.options
			}

			backend, err := NewMemoryBackend(testCase.options)

			if testCase.wantErr != "" {
				require.ErrorContains(t, err, testCase.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.wantMaximum, backend.options.MaximumSessions)
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

func TestMemoryBackendRevocationMarkerCountsAsSession(t *testing.T) {
	clock := newTestClock()
	backend, err := NewMemoryBackend(&MemoryBackendOptions{MaximumSessions: 2})
	require.NoError(t, err)
	backend.now = clock.now
	require.NoError(t, backend.Put(t.Context(), "live", "key", []byte("value"), 2*time.Hour))
	require.NoError(t, backend.Revoke(t.Context(), "revoked", time.Hour))

	require.NoError(t, backend.Revoke(t.Context(), "second", 3*time.Hour))

	require.Len(t, backend.sessions, 2)
	require.NotContains(t, backend.sessions, "revoked")
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
