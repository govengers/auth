package backendtest_test

import (
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
	for entry := range b.values {
		if entry[0] == sessionID {
			delete(b.values, entry)
		}
	}
	b.revoked[sessionID] = b.now.Add(ttl)
	return nil
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
