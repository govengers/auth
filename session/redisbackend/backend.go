package redisbackend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/govengers/auth/session"
)

const defaultKeyPrefix = "session"

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

	// popScript returns and deletes the value in one step.
	// KEYS: value, index.
	popScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if v then
  redis.call('DEL', KEYS[1])
  redis.call('SREM', KEYS[2], KEYS[1])
end
return v
`)

	// revokeScript deletes every indexed value and writes the marker.
	// KEYS: marker, index. ARGV: ttl in ms.
	revokeScript = redis.NewScript(`
for _, k in ipairs(redis.call('SMEMBERS', KEYS[2])) do redis.call('DEL', k) end
redis.call('DEL', KEYS[2])
redis.call('SET', KEYS[1], '1', 'PX', ARGV[1])
return 1
`)
)

// Options configures New.
type Options struct {
	Client    redis.UniversalClient // required; the caller owns and closes it
	KeyPrefix string                // default "session"; must not contain '{' or '}' (they delimit the hash tag)
}

// Backend implements session.Backend on Redis. One string per value plus a set indexing the keys of
// the session; the layout is <prefix>:{<sessionID>} (index), <prefix>:{<sessionID>}:<key> (value) and
// <prefix>:{<sessionID>}#revoked (revocation marker). It is safe for concurrent use.
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

// Put stores value under (sessionID, key) for ttl; session.ErrSessionRevoked when sessionID carries a marker.
// Every method refuses an empty sessionID and one containing '{' or '}' with an error.
func (b *Backend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	keys := []string{b.markerKey(sessionID), b.valueKey(sessionID, key), b.indexKey(sessionID)}
	stored, err := putScript.Run(ctx, b.client, keys, value, milliseconds(ttl)).Int()
	if err != nil {
		return dependencyError("store session value", err)
	}
	if stored == 0 {
		return session.ErrSessionRevoked
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

// Pop returns the live value under (sessionID, key) and deletes it in one atomic step.
func (b *Backend) Pop(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, false, err
	}
	value, err := popScript.Run(ctx, b.client, []string{b.valueKey(sessionID, key), b.indexKey(sessionID)}).Text()
	return valueOrAbsent([]byte(value), err, "pop session value")
}

// Revoke deletes every key of sessionID and writes a marker that refuses Puts for ttl.
func (b *Backend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	err := revokeScript.Run(ctx, b.client, []string{b.markerKey(sessionID), b.indexKey(sessionID)}, milliseconds(ttl)).Err()
	if err != nil {
		return dependencyError("revoke session", err)
	}
	return nil
}

func (b *Backend) indexKey(sessionID string) string {
	return b.prefix + ":{" + sessionID + "}"
}

func (b *Backend) markerKey(sessionID string) string {
	return b.indexKey(sessionID) + "#revoked"
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
		return nil, false, dependencyError(operation, err)
	}
	return value, true, nil
}

// dependencyError keeps the message of a go-redis error and drops its chain, so callers cannot
// start matching on the dependency's errors (LIB-010).
func dependencyError(operation string, err error) error {
	return fmt.Errorf("redis session backend: %s: %v", operation, err) //nolint:errorlint // LIB-010: go-redis errors are not part of this package's API
}
