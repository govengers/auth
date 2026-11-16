package postgresbackend

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/session"
)

// putValue refuses a revoked session and stores the value, both on the session's row lock: the upsert of
// the session row locks it (and waits for a running Revoke), and its WHERE sees the marker of a Revoke that
// committed meanwhile, so no value lands after a revocation. The session row's expiry only grows, so it
// outlives every value it holds. One row affected: stored; none: revoked.
// $1 session ID, $2 key, $3 value, $4 value expiry, $5 now.
const putValue = `
WITH session AS (
    INSERT INTO govengers_auth_sessions AS stored (session_id, expires_at) VALUES ($1, $4)
    ON CONFLICT (session_id) DO UPDATE SET expires_at = greatest(stored.expires_at, excluded.expires_at)
    WHERE stored.revoked_until IS NULL OR stored.revoked_until <= $5
    RETURNING 1
)
INSERT INTO govengers_auth_session_values (session_id, key, value, expires_at)
SELECT $1, $2, $3, $4 FROM session
ON CONFLICT (session_id, key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`

const getValue = `
SELECT value FROM govengers_auth_session_values WHERE session_id = $1 AND key = $2 AND expires_at > $3`

// popValue deletes and returns the live value; of two concurrent Pops the second waits for the first's row
// lock and then finds the row gone.
const popValue = `
DELETE FROM govengers_auth_session_values WHERE session_id = $1 AND key = $2 AND expires_at > $3
RETURNING value`

// swapValue replaces the live value while it equals the expected one, keeping its expiry; a concurrent
// swap re-checks the condition on the row it waited for.
const swapValue = `
UPDATE govengers_auth_session_values SET value = $4
WHERE session_id = $1 AND key = $2 AND value = $3 AND expires_at > $5`

// lockSession takes the session row's lock, so a Put waits for the revocation, and a Put that held it
// first has committed before revokeValues reads the values.
const lockSession = `SELECT 1 FROM govengers_auth_sessions WHERE session_id = $1 FOR UPDATE`

// revokeValues deletes every value and writes the marker for ttl, or until the latest live value would
// have expired when that is sooner; without a live value the session row stays as it is (a marker of an
// earlier revocation stays). $1 session ID, $2 now, $3 now plus ttl.
const revokeValues = `
WITH deleted AS (
    DELETE FROM govengers_auth_session_values WHERE session_id = $1 RETURNING expires_at
), latest AS (
    SELECT max(expires_at) AS expires_at FROM deleted WHERE expires_at > $2
)
UPDATE govengers_auth_sessions SET revoked_until = least(latest.expires_at, $3)
FROM latest WHERE session_id = $1 AND latest.expires_at IS NOT NULL`

// sweepValues never waits for a row lock: a Revoke holds its session's row and deletes the values in key
// order, so a sweep waiting for one of them in scan order could deadlock with it. A locked row goes with the
// next sweep.
const sweepValues = `
DELETE FROM govengers_auth_session_values WHERE (session_id, key) IN (
    SELECT session_id, key FROM govengers_auth_session_values WHERE expires_at <= $1 FOR UPDATE SKIP LOCKED
)`

// sweepSessions deletes the sessions whose values and marker have all expired: a session row's expiry is
// never before its values' or its marker's. A Put racing it holds the row lock; the delete then re-checks
// the expiry the Put raised and keeps the row.
const sweepSessions = `DELETE FROM govengers_auth_sessions WHERE expires_at <= $1`

// Options configures New.
type Options struct {
	Pool *pgxpool.Pool // required; its search_path must reach the tables of MigrationV1; the caller owns and closes it
}

// Backend implements session.Backend on PostgreSQL. Expiry is decided on the application's clock, so
// replicas need synchronized clocks (NTP). Expired rows stay until Sweep deletes them. It is safe for
// concurrent use.
type Backend struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ session.Backend = (*Backend)(nil)

// New returns a Backend on options.Pool.
func New(options *Options) (*Backend, error) {
	if options == nil || options.Pool == nil {
		return nil, errors.New("postgres session backend: Options.Pool is required")
	}
	return &Backend{pool: options.Pool, now: time.Now}, nil
}

// Put stores value under (sessionID, key) for ttl; session.ErrRevoked when sessionID carries a marker.
// Every method refuses an empty sessionID with an error.
func (b *Backend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	now := b.now()
	tag, err := b.pool.Exec(ctx, putValue, sessionID, key, value, now.Add(ttl), now)
	if err != nil {
		return dependency.Error("postgres session backend: store session value", err)
	}
	if tag.RowsAffected() == 0 {
		return session.ErrRevoked
	}
	return nil
}

// Get returns the live value under (sessionID, key).
func (b *Backend) Get(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, false, err
	}
	return b.queryValue(ctx, "read session value", getValue, sessionID, key, b.now())
}

// Pop returns the live value under (sessionID, key) and deletes it in one statement.
func (b *Backend) Pop(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, false, err
	}
	return b.queryValue(ctx, "pop session value", popValue, sessionID, key, b.now())
}

// CompareAndSwap replaces the live value under (sessionID, key) with value, keeping its expiry, when it
// still equals previous.
func (b *Backend) CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	if err := validateSessionID(sessionID); err != nil {
		return false, err
	}
	tag, err := b.pool.Exec(ctx, swapValue, sessionID, key, previous, value, b.now())
	if err != nil {
		return false, dependency.Error("postgres session backend: swap session value", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Revoke deletes every value of sessionID. When there was a live one, it writes a marker that refuses Puts
// for ttl, or until the latest of the deleted values would have expired when that is sooner. It runs in
// its own READ COMMITTED transaction whatever the server's default, so its read of the values sees every
// Put that committed before it took the session's lock.
func (b *Backend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	now := b.now()
	err := pgx.BeginTxFunc(ctx, b.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(transaction pgx.Tx) error {
		tag, err := transaction.Exec(ctx, lockSession, sessionID)
		if err != nil || tag.RowsAffected() == 0 {
			return err // no session row: no values, nothing to mark
		}
		_, err = transaction.Exec(ctx, revokeValues, sessionID, now, now.Add(ttl))
		return err
	})
	if err != nil {
		return dependency.Error("postgres session backend: revoke session", err)
	}
	return nil
}

// Sweep deletes expired values and the sessions whose values and revocation marker have all expired, and
// returns the number of rows it deleted; an expired value another transaction holds locked is left to the
// next Sweep. Expired rows never count as live, so Sweep only frees space:
// schedule it (e.g. every few minutes from one replica, a govengers/jobs schedule) on a busy backend.
func (b *Backend) Sweep(ctx context.Context) (int64, error) {
	now := b.now()
	var deleted int64
	// shortcut: one statement per table, unbatched; split into LIMITed batches if a sweep ever deletes millions of rows.
	for _, statement := range []string{sweepValues, sweepSessions} {
		tag, err := b.pool.Exec(ctx, statement, now)
		if err != nil {
			return deleted, dependency.Error("postgres session backend: sweep expired sessions", err)
		}
		deleted += tag.RowsAffected()
	}
	return deleted, nil
}

// queryValue runs a statement returning at most one value: no row means absent.
func (b *Backend) queryValue(ctx context.Context, operation, statement string, arguments ...any) ([]byte, bool, error) {
	var value []byte
	err := b.pool.QueryRow(ctx, statement, arguments...).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, dependency.Error("postgres session backend: "+operation, err)
	}
	return value, true, nil
}

// validateSessionID refuses the empty ID. The ID is not part of the message.
func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return errors.New("postgres session backend: session ID must be non-empty")
	}
	return nil
}
