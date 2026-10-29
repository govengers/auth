package session

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"
)

const defaultMaximumSessions = 100000

// MemoryBackendOptions configures NewMemoryBackend.
type MemoryBackendOptions struct {
	MaximumSessions int // default 100000; when full: expired entries are dropped, then the session expiring soonest is evicted
}

// MemoryBackend implements Backend with a map and one mutex; expiry is lazy (no goroutine). It is
// correct for exactly one replica and safe for concurrent use.
// ponytail: O(n) eviction scan when full; shard or use Redis if that ever shows in profiles.
type MemoryBackend struct {
	options  MemoryBackendOptions
	mutex    sync.Mutex
	sessions map[string]*memorySession
	now      func() time.Time
}

type memorySession struct {
	values       map[string]memoryValue
	revokedUntil time.Time
}

type memoryValue struct {
	value     []byte
	expiresAt time.Time
}

// NewMemoryBackend returns the in-process backend: correct for exactly one replica. nil options allowed.
func NewMemoryBackend(options *MemoryBackendOptions) (*MemoryBackend, error) {
	var resolved MemoryBackendOptions
	if options != nil {
		resolved = *options
	}
	if resolved.MaximumSessions < 0 {
		return nil, fmt.Errorf("memory session backend: MaximumSessions %d is negative", resolved.MaximumSessions)
	}
	if resolved.MaximumSessions == 0 {
		resolved.MaximumSessions = defaultMaximumSessions
	}
	return &MemoryBackend{options: resolved, sessions: map[string]*memorySession{}, now: time.Now}, nil
}

// Put stores a copy of value under (sessionID, key) for ttl; ErrSessionRevoked when sessionID is revoked.
func (b *MemoryBackend) Put(_ context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	now := b.now()
	entry, found := b.sessions[sessionID]
	if found && entry.revoked(now) {
		return ErrSessionRevoked
	}
	if !found {
		entry = b.add(sessionID, &memorySession{values: map[string]memoryValue{}}, now)
	}
	entry.values[key] = memoryValue{value: slices.Clone(value), expiresAt: now.Add(ttl)}
	return nil
}

// Get returns a copy of the live value under (sessionID, key).
func (b *MemoryBackend) Get(_ context.Context, sessionID, key string) ([]byte, bool, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	value, found := b.lookup(sessionID, key, b.now())
	return value, found, nil
}

// Pop returns the live value under (sessionID, key) and deletes it.
func (b *MemoryBackend) Pop(_ context.Context, sessionID, key string) ([]byte, bool, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	now := b.now()
	value, found := b.lookup(sessionID, key, now)
	if found {
		b.remove(sessionID, key, now)
	}
	return value, found, nil
}

// Revoke deletes every value of sessionID and writes a marker that refuses Puts for ttl.
func (b *MemoryBackend) Revoke(_ context.Context, sessionID string, ttl time.Duration) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	now := b.now()
	delete(b.sessions, sessionID)
	b.add(sessionID, &memorySession{values: map[string]memoryValue{}, revokedUntil: now.Add(ttl)}, now)
	return nil
}

// lookup returns a copy of the live value. b.mutex must be held.
func (b *MemoryBackend) lookup(sessionID, key string, now time.Time) ([]byte, bool) {
	entry, found := b.sessions[sessionID]
	if !found {
		return nil, false
	}
	item, found := entry.values[key]
	if !found || !item.expiresAt.After(now) {
		return nil, false
	}
	return slices.Clone(item.value), true
}

// remove deletes one value, and the session entry once it holds nothing. b.mutex must be held.
func (b *MemoryBackend) remove(sessionID, key string, now time.Time) {
	entry := b.sessions[sessionID]
	delete(entry.values, key)
	if len(entry.values) == 0 && !entry.revoked(now) {
		delete(b.sessions, sessionID)
	}
}

// add stores a new session entry, making room first when the backend is full. b.mutex must be held.
func (b *MemoryBackend) add(sessionID string, entry *memorySession, now time.Time) *memorySession {
	if len(b.sessions) >= b.options.MaximumSessions {
		b.makeRoom(now)
	}
	b.sessions[sessionID] = entry
	return entry
}

// makeRoom drops expired sessions and, when that frees nothing, evicts the session expiring soonest.
// b.mutex must be held.
func (b *MemoryBackend) makeRoom(now time.Time) {
	maps.DeleteFunc(b.sessions, func(_ string, entry *memorySession) bool {
		return !entry.expiresAt().After(now)
	})
	if len(b.sessions) < b.options.MaximumSessions {
		return
	}
	delete(b.sessions, b.soonestExpiring())
}

func (b *MemoryBackend) soonestExpiring() string {
	var soonestID string
	var soonest time.Time
	for sessionID, entry := range b.sessions {
		if expiresAt := entry.expiresAt(); soonestID == "" || expiresAt.Before(soonest) {
			soonestID, soonest = sessionID, expiresAt
		}
	}
	return soonestID
}

func (m *memorySession) revoked(now time.Time) bool {
	return m.revokedUntil.After(now)
}

// expiresAt is when the last value or the revocation marker of the session expires.
func (m *memorySession) expiresAt() time.Time {
	latest := m.revokedUntil
	for _, item := range m.values {
		if item.expiresAt.After(latest) {
			latest = item.expiresAt
		}
	}
	return latest
}
