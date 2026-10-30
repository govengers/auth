package redisbackend

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/session"
)

const (
	defaultKeyPrefix = "session"
	// receiptTTL keeps the result of a Pop or CompareAndSwap for a retry of the same call; it outlives
	// go-redis's retries of a lost reply (MaxRetries times read timeout plus backoff, about 11 s with the defaults).
	receiptTTL = time.Minute
)

// Lua scripts keep each operation atomic on the slot of one session. They are read-only package values.
var (
	// putScript refuses a revoked session, stores the value and indexes it.
	// KEYS: marker, value, index. ARGV: value, ttl in ms. Returns 0 when revoked, 1 when stored.
	putScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
redis.call('SADD', KEYS[3], KEYS[2])
if redis.call('PTTL', KEYS[3]) < tonumber(ARGV[2]) then redis.call('PEXPIRE', KEYS[3], ARGV[2]) end
return 1
`)

	// popScript returns and deletes the value in one step. It keeps the value under a receipt named by the
	// caller's random token, so a client retrying the script after a lost reply (go-redis does by default)
	// gets the value again instead of "absent" (RES-004: the token is the idempotency key). The receipt is
	// read first, so a retry never consumes a value written after the lost attempt.
	// KEYS: value, index, receipt. ARGV: receipt ttl in ms.
	popScript = redis.NewScript(`
local popped = redis.call('GET', KEYS[3])
if popped then return popped end
local v = redis.call('GET', KEYS[1])
if not v then return v end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], KEYS[1])
redis.call('SET', KEYS[3], v, 'PX', ARGV[1])
return v
`)

	// swapScript replaces the value, keeping its expiry, when it still equals the expected one. A revoked
	// session holds no value, so it never swaps. Like popScript it leaves a receipt under the caller's token,
	// so a retry after a lost reply reports the swap the lost attempt made, even when the value changed since.
	// KEYS: value, receipt. ARGV: expected value, new value, receipt ttl in ms. Returns 1 when swapped, else 0.
	swapScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then return 1 end
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
redis.call('SET', KEYS[2], '1', 'PX', ARGV[3])
return 1
`)

	// revokeScript deletes every indexed value and writes the marker for ttl, or until the latest of the
	// values still stored would expire when that is sooner; without a live value no marker. The index TTL is
	// no measure: it only ever grows, so it outlives replaced, popped and expired values.
	// KEYS: marker, index. ARGV: ttl in ms.
	revokeScript = redis.NewScript(`
local latest = 0
for _, k in ipairs(redis.call('SMEMBERS', KEYS[2])) do
  latest = math.max(latest, redis.call('PTTL', k))
  redis.call('DEL', k)
end
redis.call('DEL', KEYS[2])
local ttl = math.min(latest, tonumber(ARGV[1]))
if ttl > 0 then redis.call('SET', KEYS[1], '1', 'PX', ttl) end
return 1
`)
)

// Options configures New.
type Options struct {
	Client    redis.UniversalClient // required; the caller owns and closes it
	KeyPrefix string                // default "session"; must not contain '{' or '}' (they delimit the hash tag)
}

// Backend implements session.Backend on Redis. One string per value plus a set indexing the keys of
// the session; the layout is <prefix>:{<sessionID>} (index), <prefix>:{<sessionID>}:<key> (value),
// <prefix>:{<sessionID>}#revoked (revocation marker) and <prefix>:{<sessionID>}#popped:<token> and
// #swapped:<token> (the result of one Pop or CompareAndSwap, kept one minute for its retry). It is safe for concurrent use.
type Backend struct {
	client redis.UniversalClient
	prefix string
}

var _ session.Backend = (*Backend)(nil)

// New returns a Backend on options.Client. The options are copied; the client stays with the caller.
func New(options *Options) (*Backend, error) {
	if options == nil {
		return nil, errors.New("redis session backend: options are required")
	}
	if options.Client == nil {
		return nil, errors.New("redis session backend: Client is required")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = defaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, fmt.Errorf("redis session backend: KeyPrefix %q must not contain '{' or '}'", prefix)
	}
	return &Backend{client: options.Client, prefix: prefix}, nil
}

// Put stores value under (sessionID, key) for ttl; session.ErrRevoked when sessionID carries a marker.
// Every method refuses an empty sessionID and one containing '{' or '}' with an error.
func (b *Backend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	keys := []string{b.markerKey(sessionID), b.valueKey(sessionID, key), b.indexKey(sessionID)}
	stored, err := putScript.Run(ctx, b.client, keys, value, milliseconds(ttl)).Int()
	if err != nil {
		return dependency.Error("redis session backend: store session value", err)
	}
	if stored == 0 {
		return session.ErrRevoked
	}
	return nil
}

// Get returns the live value under (sessionID, key).
func (b *Backend) Get(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, false, err
	}
	value, err := b.client.Get(ctx, b.valueKey(sessionID, key)).Bytes()
	return valueOrAbsent(value, err, "read session value")
}

// Pop returns the live value under (sessionID, key) and deletes it in one atomic step; a client retry of
// the step after a lost reply returns the same value.
func (b *Backend) Pop(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, false, err
	}
	keys := []string{b.valueKey(sessionID, key), b.indexKey(sessionID), b.receiptKey(sessionID, "popped")}
	value, err := popScript.Run(ctx, b.client, keys, receiptTTL.Milliseconds()).Text()
	return valueOrAbsent([]byte(value), err, "pop session value")
}

// CompareAndSwap replaces the live value under (sessionID, key) with value, keeping its expiry, when it
// still equals previous; a client retry of the step after a lost reply reports the same result.
func (b *Backend) CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	if err := validateSessionID(sessionID); err != nil {
		return false, err
	}
	keys := []string{b.valueKey(sessionID, key), b.receiptKey(sessionID, "swapped")}
	swapped, err := swapScript.Run(ctx, b.client, keys, previous, value, receiptTTL.Milliseconds()).Int()
	if err != nil {
		return false, dependency.Error("redis session backend: swap session value", err)
	}
	return swapped == 1, nil
}

// Revoke deletes every key of sessionID. When there was any, it writes a marker that refuses Puts for ttl,
// or until the latest of the deleted values would have expired when that is sooner.
func (b *Backend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	err := revokeScript.Run(ctx, b.client, []string{b.markerKey(sessionID), b.indexKey(sessionID)}, milliseconds(ttl)).Err()
	if err != nil {
		return dependency.Error("redis session backend: revoke session", err)
	}
	return nil
}

func (b *Backend) indexKey(sessionID string) string {
	return b.prefix + ":{" + sessionID + "}"
}

func (b *Backend) markerKey(sessionID string) string {
	return b.indexKey(sessionID) + "#revoked"
}

// receiptKey names the one-minute receipt of a single call, keyed by a random token.
func (b *Backend) receiptKey(sessionID, operation string) string {
	return b.indexKey(sessionID) + "#" + operation + ":" + rand.Text()
}

func (b *Backend) valueKey(sessionID, key string) string {
	return b.indexKey(sessionID) + ":" + key
}

// validateSessionID keeps all keys of a session in one cluster slot: Redis hashes the text between the
// first '{' and the next '}' of a key, and an empty tag makes it hash the whole key. The ID is not
// part of the message.
func validateSessionID(sessionID string) error {
	if sessionID == "" || strings.ContainsAny(sessionID, "{}") {
		return errors.New("redis session backend: session ID must be non-empty and must not contain '{' or '}'")
	}
	return nil
}

// milliseconds converts ttl for Redis, which rejects a zero expiry: anything shorter than 1 ms counts as 1 ms.
func milliseconds(ttl time.Duration) int64 {
	return max(ttl.Milliseconds(), 1)
}

// valueOrAbsent maps a reply to (value, found, error): redis.Nil means absent, any other error is a failure.
func valueOrAbsent(value []byte, err error, operation string) ([]byte, bool, error) {
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, dependency.Error("redis session backend: "+operation, err)
	}
	return value, true, nil
}
