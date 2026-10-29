package session

import (
	"bytes"
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
	// MaximumSessions defaults to 100000. When full, expired entries are dropped, then the entry expiring
	// soonest is evicted, a live revocation marker included.
	MaximumSessions int
}

// MemoryBackend implements Backend with a map and one mutex; expiry is lazy (no goroutine). It is
// correct for exactly one replica and safe for concurrent use.
// A full backend evicts revocation markers like sessions, so a flood of login starts cannot block every new
// session; the cost is that an evicted marker no longer refuses a Put for its revoked session. Nothing can
// give that session an identity again (SaveIdentity needs a live one or a Start handle, the Guard refreshes
// by CompareAndSwap), but a provider or application value may land in it. Meant for one replica at
// non-production scale; use Redis in production.
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
		b.makeRoom(now)
		entry = &memorySession{values: map[string]memoryValue{}}
		b.sessions[sessionID] = entry
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

// CompareAndSwap replaces the live value under (sessionID, key) with a copy of value, keeping its expiry,
// when it equals previous.
func (b *MemoryBackend) CompareAndSwap(_ context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	current, found := b.lookup(sessionID, key, b.now())
	if !found || !bytes.Equal(current, previous) {
		return false, nil
	}
	values := b.sessions[sessionID].values
	values[key] = memoryValue{value: slices.Clone(value), expiresAt: values[key].expiresAt}
	return true, nil
}

// Revoke deletes every value of sessionID. When there was any, the entry becomes a marker that refuses Puts
// for ttl, or until the latest of those values would have expired when that is sooner; it never takes a new slot.
func (b *MemoryBackend) Revoke(_ context.Context, sessionID string, ttl time.Duration) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	entry, found := b.sessions[sessionID]
	if !found || len(entry.values) == 0 {
		return nil
	}
	now := b.now()
	revokedUntil := entry.expiresAt()
	if limit := now.Add(ttl); limit.Before(revokedUntil) {
		revokedUntil = limit
	}
	if !revokedUntil.After(now) {
		delete(b.sessions, sessionID)
		return nil
	}
	b.sessions[sessionID] = &memorySession{values: map[string]memoryValue{}, revokedUntil: revokedUntil}
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

// makeRoom frees a slot for a new session when the backend is full: it drops expired entries and, when
// that frees nothing, evicts the entry expiring soonest, a revocation marker included. b.mutex must be held.
func (b *MemoryBackend) makeRoom(now time.Time) {
	if len(b.sessions) < b.options.MaximumSessions {
		return
	}
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
