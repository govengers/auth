package session

import (
	"testing"
	"time"
)

// NewMemoryBackendOnTestClock returns a memory backend on its own test clock and the function that
// moves that clock forward, for the conformance run in package session_test.
func NewMemoryBackendOnTestClock(t *testing.T) (*MemoryBackend, func(duration time.Duration)) {
	t.Helper()
	clock := newTestClock()
	return newTestMemoryBackend(t, clock), clock.advance
}
