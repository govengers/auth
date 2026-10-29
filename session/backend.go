package session

import (
	"context"
	"errors"
	"time"
)

// ErrSessionRevoked is returned by Backend.Put for a session that carries a revocation marker.
// Store and Session translate it into an auth.ErrUnauthenticated refusal.
var ErrSessionRevoked = errors.New("session revoked")

// Backend stores the server-side half of sessions: one opaque, already encrypted value per (sessionID, key).
// sessionID is a non-secret identifier derived from the cookie (SHA-256), never the cookie value.
// Every operation is atomic per key; Put is serialized against Revoke of the same sessionID, so after
// Revoke returned no Put for that sessionID succeeds until the marker expires or a full backend evicts it
// (MemoryBackend; Redis under its own eviction policy). A marker never outlives the values it replaced,
// and a sessionID without values gets none: revoking unknown IDs stores nothing.
// Values expire after their own ttl, which is always positive. Applications may implement it (e.g. on Postgres); share one backend
// between replicas. Implementations must be safe for concurrent use.
type Backend interface {
	// Put stores value under (sessionID, key) for ttl, replacing an existing value; ErrSessionRevoked when revoked.
	Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error
	// Get returns the live value under (sessionID, key); found is false when there is none or it expired.
	Get(ctx context.Context, sessionID, key string) (value []byte, found bool, err error)
	// Pop returns and deletes the live value in one step: of two concurrent Pops at most one finds the value.
	Pop(ctx context.Context, sessionID, key string) (value []byte, found bool, err error)
	// CompareAndSwap replaces the live value under (sessionID, key) with value in one step, keeping its expiry,
	// only when it still equals previous; swapped is false when it changed, expired or was revoked meanwhile.
	CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (swapped bool, err error)
	// Revoke deletes every key of sessionID. When there was any, it writes a marker living ttl, or until the
	// latest of the deleted values would have expired when that is sooner.
	Revoke(ctx context.Context, sessionID string, ttl time.Duration) error
}
