package session

import (
	"bytes"
	"container/heap"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

const (
	defaultMaximumSessions = 100000
	defaultMaximumBytes    = 64 << 20
)

// MemoryBackendOptions configures NewMemoryBackend.
type MemoryBackendOptions struct {
	// MaximumSessions defaults to 100000, MaximumBytes (session IDs, keys and values held) to 64 MiB. When a
	// write would pass either (a replacement counts only what it adds), expired entries are dropped, then the entries expiring soonest are evicted, a
	// live revocation marker included. A single value that cannot fit is refused.
	MaximumSessions int
	MaximumBytes    int
}

// MemoryBackend implements Backend with a map and one mutex; expiry is lazy (no goroutine). It is
// correct for exactly one replica and safe for concurrent use.
// A full backend evicts revocation markers like sessions, so a flood of login starts cannot block every new
// session; the cost is that an evicted marker no longer refuses a Put for its revoked session. Nothing can
// give that session an identity again (SaveIdentity and the Guard swap against a live identity, and only the
// first save of a Start handle writes without one), but a provider or application value may land in it. Meant for one replica at
// non-production scale; use Redis in production.
type MemoryBackend struct {
	options     MemoryBackendOptions
	mutex       sync.Mutex
	sessions    map[string]*memorySession
	expiries    expiryQueue // every entry of sessions, soonest expiring first: eviction costs O(log n), not a scan
	storedBytes int         // of every session ID, key and value in sessions
	now         func() time.Time
}

type memorySession struct {
	sessionID    string
	values       map[string]memoryValue
	revokedUntil time.Time
	expiresAt    time.Time // when the last value or the revocation marker expires; kept by updateExpiry
	position     int       // index in MemoryBackend.expiries
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
	if resolved.MaximumBytes < 0 {
		return nil, fmt.Errorf("memory session backend: MaximumBytes %d is negative", resolved.MaximumBytes)
	}
	if resolved.MaximumBytes == 0 {
		resolved.MaximumBytes = defaultMaximumBytes
	}
	return &MemoryBackend{options: resolved, sessions: map[string]*memorySession{}, now: time.Now}, nil
}

// Put stores a copy of value under (sessionID, key) for ttl; ErrRevoked when sessionID is revoked.
func (b *MemoryBackend) Put(_ context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	now := b.now()
	entry, found := b.sessions[sessionID]
	if found && entry.revoked(now) {
		return ErrRevoked
	}
	size := len(sessionID) + len(key) + len(value)
	if size > b.options.MaximumBytes {
		return fmt.Errorf("memory session backend: a value of %d bytes cannot fit in MaximumBytes %d", size, b.options.MaximumBytes)
	}
	b.makeRoom(now, !found, growth(entry, key, len(value), size))
	if _, kept := b.sessions[sessionID]; found && !kept { // evicted to make room: it comes back as a new session
		b.makeRoom(now, true, size)
	}
	entry, found = b.sessions[sessionID]
	if !found {
		entry = b.addSession(sessionID, &memorySession{values: map[string]memoryValue{}})
	}
	b.storeValue(entry, key, memoryValue{value: slices.Clone(value), expiresAt: now.Add(ttl)})
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
	now := b.now()
	current, found := b.lookup(sessionID, key, now)
	if !found || !bytes.Equal(current, previous) {
		return false, nil
	}
	if growth := len(value) - len(current); growth > 0 {
		if len(sessionID)+len(key)+len(value) > b.options.MaximumBytes {
			return false, fmt.Errorf("memory session backend: a value of %d bytes cannot fit in MaximumBytes %d", len(value), b.options.MaximumBytes)
		}
		b.makeRoom(now, false, growth)
		if _, found := b.lookup(sessionID, key, now); !found {
			return false, nil // evicted to make room: as if it expired meanwhile
		}
	}
	entry := b.sessions[sessionID]
	b.storeValue(entry, key, memoryValue{value: slices.Clone(value), expiresAt: entry.values[key].expiresAt})
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
	revokedUntil := entry.expiresAt
	if limit := now.Add(ttl); limit.Before(revokedUntil) {
		revokedUntil = limit
	}
	b.deleteSession(sessionID)
	if revokedUntil.After(now) {
		b.addSession(sessionID, &memorySession{values: map[string]memoryValue{}, revokedUntil: revokedUntil})
	}
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
	b.storedBytes -= len(key) + len(entry.values[key].value)
	delete(entry.values, key)
	if len(entry.values) == 0 && !entry.revoked(now) {
		b.deleteSession(sessionID)
		return
	}
	b.updateExpiry(entry)
}

// makeRoom frees room for a write that adds a session (newSession) and up to size bytes when it would pass
// MaximumSessions or MaximumBytes: it drops expired entries and then evicts the entries expiring soonest,
// a revocation marker included, until the write fits. b.mutex must be held.
func (b *MemoryBackend) makeRoom(now time.Time, newSession bool, size int) {
	if b.fits(newSession, size) {
		return
	}
	for b.expiries.Len() > 0 && !b.expiries.soonest().expiresAt.After(now) {
		b.deleteSession(b.expiries.soonest().sessionID)
	}
	for b.expiries.Len() > 0 && !b.fits(newSession, size) {
		b.deleteSession(b.expiries.soonest().sessionID)
	}
}

func (b *MemoryBackend) fits(newSession bool, size int) bool {
	sessions := len(b.sessions)
	if newSession {
		sessions++
	}
	return sessions <= b.options.MaximumSessions && b.storedBytes+size <= b.options.MaximumBytes
}

// growth is the net number of bytes storing valueBytes under key adds to entry (nil: a new session of
// size bytes); a replacement counts only its difference, so it never evicts what it does not need to.
func growth(entry *memorySession, key string, valueBytes, size int) int {
	if entry == nil {
		return size
	}
	if previous, found := entry.values[key]; found {
		return valueBytes - len(previous.value)
	}
	return len(key) + valueBytes
}

// addSession stores entry, a new or a revoked session without values, under sessionID. b.mutex must be held.
func (b *MemoryBackend) addSession(sessionID string, entry *memorySession) *memorySession {
	entry.sessionID, entry.expiresAt = sessionID, entry.latestExpiry()
	b.sessions[sessionID] = entry
	heap.Push(&b.expiries, entry)
	b.storedBytes += len(sessionID)
	return entry
}

// deleteSession drops sessionID with every value. b.mutex must be held.
func (b *MemoryBackend) deleteSession(sessionID string) {
	entry, found := b.sessions[sessionID]
	if !found {
		return
	}
	b.storedBytes -= len(sessionID)
	for key, item := range entry.values {
		b.storedBytes -= len(key) + len(item.value)
	}
	delete(b.sessions, sessionID)
	heap.Remove(&b.expiries, entry.position)
}

// storeValue sets key of entry to item. b.mutex must be held.
func (b *MemoryBackend) storeValue(entry *memorySession, key string, item memoryValue) {
	if previous, found := entry.values[key]; found {
		b.storedBytes -= len(key) + len(previous.value)
	}
	entry.values[key] = item
	b.storedBytes += len(key) + len(item.value)
	b.updateExpiry(entry)
}

// updateExpiry moves entry to its place in b.expiries after its values changed. b.mutex must be held.
func (b *MemoryBackend) updateExpiry(entry *memorySession) {
	entry.expiresAt = entry.latestExpiry()
	heap.Fix(&b.expiries, entry.position)
}

func (m *memorySession) revoked(now time.Time) bool {
	return m.revokedUntil.After(now)
}

// latestExpiry is when the last value or the revocation marker of the session expires.
func (m *memorySession) latestExpiry() time.Time {
	latest := m.revokedUntil
	for _, item := range m.values {
		if item.expiresAt.After(latest) {
			latest = item.expiresAt
		}
	}
	return latest
}

// expiryQueue is a min-heap (container/heap) of sessions by expiresAt.
type expiryQueue struct {
	sessions    []*memorySession
	comparisons int // the work done so far, for the test that eviction stays O(log n)
}

func (q *expiryQueue) soonest() *memorySession { return q.sessions[0] }

func (q *expiryQueue) Len() int { return len(q.sessions) }

func (q *expiryQueue) Less(first, second int) bool {
	q.comparisons++
	return q.sessions[first].expiresAt.Before(q.sessions[second].expiresAt)
}

func (q *expiryQueue) Swap(first, second int) {
	q.sessions[first], q.sessions[second] = q.sessions[second], q.sessions[first]
	q.sessions[first].position, q.sessions[second].position = first, second
}

func (q *expiryQueue) Push(item any) {
	entry := item.(*memorySession)
	entry.position = len(q.sessions)
	q.sessions = append(q.sessions, entry)
}

func (q *expiryQueue) Pop() any {
	last := q.sessions[len(q.sessions)-1]
	q.sessions[len(q.sessions)-1] = nil
	q.sessions = q.sessions[:len(q.sessions)-1]
	return last
}
