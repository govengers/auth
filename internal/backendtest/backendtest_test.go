package backendtest_test

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/govengers/auth/internal/backendtest"
	"github.com/govengers/auth/session"
)

// referenceBackend is the smallest correct session.Backend on a fake clock: it proves that the suite
// accepts a backend that keeps the contract. session.MemoryBackend runs the suite in its own tests.
type referenceBackend struct {
	mutex   sync.Mutex
	now     time.Time
	values  map[[2]string]referenceValue
	revoked map[string]time.Time
}

type referenceValue struct {
	value     []byte
	expiresAt time.Time
}

func (b *referenceBackend) Put(_ context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.revoked[sessionID].After(b.now) {
		return session.ErrSessionRevoked
	}
	b.values[[2]string{sessionID, key}] = referenceValue{value: slices.Clone(value), expiresAt: b.now.Add(ttl)}
	return nil
}

func (b *referenceBackend) Get(_ context.Context, sessionID, key string) ([]byte, bool, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	value, found := b.live(sessionID, key)
	return value, found, nil
}

func (b *referenceBackend) Pop(_ context.Context, sessionID, key string) ([]byte, bool, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	value, found := b.live(sessionID, key)
	delete(b.values, [2]string{sessionID, key})
	return value, found, nil
}

func (b *referenceBackend) CompareAndSwap(_ context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	current, found := b.live(sessionID, key)
	if !found || !bytes.Equal(current, previous) {
		return false, nil
	}
	entry := [2]string{sessionID, key}
	b.values[entry] = referenceValue{value: slices.Clone(value), expiresAt: b.values[entry].expiresAt}
	return true, nil
}

func (b *referenceBackend) live(sessionID, key string) ([]byte, bool) {
	item, found := b.values[[2]string{sessionID, key}]
	if !found || !item.expiresAt.After(b.now) {
		return nil, false
	}
	return slices.Clone(item.value), true
}

func (b *referenceBackend) Revoke(_ context.Context, sessionID string, ttl time.Duration) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	revokedUntil := b.now
	for entry, item := range b.values {
		if entry[0] == sessionID {
			revokedUntil = later(revokedUntil, item.expiresAt)
			delete(b.values, entry)
		}
	}
	if limit := b.now.Add(ttl); limit.Before(revokedUntil) {
		revokedUntil = limit
	}
	if revokedUntil.After(b.now) {
		b.revoked[sessionID] = revokedUntil
	}
	return nil
}

func later(first, second time.Time) time.Time {
	if second.After(first) {
		return second
	}
	return first
}

func (b *referenceBackend) advance(duration time.Duration) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.now = b.now.Add(duration)
}

func TestRunAcceptsACorrectBackend(t *testing.T) {
	backendtest.Run(t, func(*testing.T) (session.Backend, func(time.Duration)) {
		backend := &referenceBackend{now: time.Unix(0, 0), values: map[[2]string]referenceValue{}, revoked: map[string]time.Time{}}
		return backend, backend.advance
	})
}
