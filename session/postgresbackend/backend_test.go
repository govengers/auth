package postgresbackend_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/govengers/postgrestest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/govengers/auth/internal/backendtest"
	"github.com/govengers/auth/session"
	"github.com/govengers/auth/session/postgresbackend"
)

// postgres gives every test a database of its own with MigrationV1 applied.
var postgres = postgrestest.New(&postgrestest.Options{
	Migrate:     postgrestest.Statements(postgresbackend.MigrationV1),
	Fingerprint: postgresbackend.MigrationV1,
})

func TestMain(m *testing.M) { goleak.VerifyTestMain(postgres.Main(m)) }

// testClock is a clock the test moves forward; the backend reads it from several goroutines.
type testClock struct {
	mutex sync.Mutex
	now   time.Time
}

func (c *testClock) read() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.now
}

func (c *testClock) advance(duration time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.now = c.now.Add(duration)
}

func newBackend(t *testing.T) (*postgresbackend.Backend, *testClock, *pgxpool.Pool) {
	t.Helper()
	pool := postgres.Pool(t)
	backend, err := postgresbackend.New(&postgresbackend.Options{Pool: pool})
	require.NoError(t, err)
	clock := &testClock{now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	postgresbackend.SetClock(backend, clock.read)
	return backend, clock, pool
}

func TestBackendConformance(t *testing.T) {
	backendtest.Run(t, func(t *testing.T) (session.Backend, func(time.Duration)) {
		backend, clock, _ := newBackend(t)
		return backend, clock.advance
	})
}

func TestNew(t *testing.T) {
	_, err := postgresbackend.New(nil)
	require.ErrorContains(t, err, "Pool is required")
	_, err = postgresbackend.New(&postgresbackend.Options{})
	require.ErrorContains(t, err, "Pool is required")
}

func TestEmptySessionIDIsRefused(t *testing.T) {
	backend, _, _ := newBackend(t)
	ctx := t.Context()

	require.ErrorContains(t, backend.Put(ctx, "", "key", []byte("value"), time.Hour), "session ID must be non-empty")
	_, _, err := backend.Get(ctx, "", "key")
	require.Error(t, err)
	_, _, err = backend.Pop(ctx, "", "key")
	require.Error(t, err)
	_, err = backend.CompareAndSwap(ctx, "", "key", nil, nil)
	require.Error(t, err)
	require.Error(t, backend.Revoke(ctx, "", time.Hour))
}

func TestSweepDeletesOnlyExpiredRows(t *testing.T) {
	backend, clock, pool := newBackend(t)
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "short", "key", []byte("value"), time.Minute))
	require.NoError(t, backend.Put(ctx, "mixed", "short", []byte("value"), time.Minute))
	require.NoError(t, backend.Put(ctx, "mixed", "long", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "revoked", "key", []byte("value"), time.Hour))
	require.NoError(t, backend.Revoke(ctx, "revoked", 30*time.Minute))
	clock.advance(2 * time.Minute)

	deleted, err := backend.Sweep(ctx)

	require.NoError(t, err)
	require.Equal(t, int64(3), deleted, "two expired values and the session of one of them")
	require.Equal(t, 2, count(t, pool, "govengers_auth_sessions"), "the mixed session and the live marker stay")
	require.Equal(t, 1, count(t, pool, "govengers_auth_session_values"))
	value, found, err := backend.Get(ctx, "mixed", "long")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "value", string(value))
	require.ErrorIs(t, backend.Put(ctx, "revoked", "key", []byte("value"), time.Hour), session.ErrRevoked)

	clock.advance(time.Hour)
	deleted, err = backend.Sweep(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(3), deleted, "the long value, its session and the expired marker")
	require.Zero(t, count(t, pool, "govengers_auth_sessions"))
	require.NoError(t, backend.Put(ctx, "revoked", "key", []byte("value"), time.Hour), "the swept marker refuses nothing")
}

// A Sweep skips an expired value whose row another transaction holds (a Revoke deleting it) instead of
// waiting for it in an order that can deadlock with that Revoke; the next sweep takes it.
func TestSweepSkipsLockedValues(t *testing.T) {
	backend, clock, pool := newBackend(t)
	ctx := t.Context()
	require.NoError(t, backend.Put(ctx, "locked", "short", []byte("value"), time.Minute))
	require.NoError(t, backend.Put(ctx, "locked", "long", []byte("value"), time.Hour))
	require.NoError(t, backend.Put(ctx, "free", "short", []byte("value"), time.Minute))
	clock.advance(2 * time.Minute)
	transaction, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = transaction.Rollback(ctx) }() // after the Commit below a no-op
	_, err = transaction.Exec(ctx, `SELECT 1 FROM govengers_auth_session_values WHERE session_id = 'locked' AND key = 'short' FOR UPDATE`)
	require.NoError(t, err)

	sweepContext, cancel := context.WithTimeout(ctx, 10*time.Second) // ends a sweep that waits for the lock
	defer cancel()
	deleted, err := backend.Sweep(sweepContext)

	require.NoError(t, err)
	require.Equal(t, int64(2), deleted, "the free value and its session")
	require.NoError(t, transaction.Commit(ctx))
	deleted, err = backend.Sweep(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted, "the value that was locked")
}

// A Put racing a Sweep of its expired session row either lands in a fresh row or raises the row's expiry
// before the Sweep re-checks it: the value is never deleted with the old row.
func TestSweepRacingPutKeepsTheValue(t *testing.T) {
	backend, clock, _ := newBackend(t)
	ctx := t.Context()
	for round := range 30 {
		sessionID := fmt.Sprintf("session-%d", round)
		require.NoError(t, backend.Put(ctx, sessionID, "old", []byte("value"), time.Minute))
		clock.advance(2 * time.Minute)
		var putError, sweepError error
		var waitGroup sync.WaitGroup
		waitGroup.Go(func() { putError = backend.Put(ctx, sessionID, "new", []byte("value"), time.Minute) })
		waitGroup.Go(func() { _, sweepError = backend.Sweep(ctx) })
		waitGroup.Wait()

		require.NoError(t, putError, "round %d", round)
		require.NoError(t, sweepError, "round %d", round)
		_, found, err := backend.Get(ctx, sessionID, "new")
		require.NoError(t, err)
		require.True(t, found, "round %d: the value put during the sweep is gone", round)
	}
}

func TestErrorsAreReportedWithoutTheirChain(t *testing.T) {
	backend, _, pool := newBackend(t)
	pool.Close()
	ctx := context.Background()

	require.ErrorContains(t, backend.Put(ctx, "s", "key", []byte("value"), time.Hour), "postgres session backend: store session value")
	_, _, err := backend.Get(ctx, "s", "key")
	require.ErrorContains(t, err, "postgres session backend: read session value")
	_, err = backend.CompareAndSwap(ctx, "s", "key", nil, nil)
	require.ErrorContains(t, err, "postgres session backend: swap session value")
	require.ErrorContains(t, backend.Revoke(ctx, "s", time.Hour), "postgres session backend: revoke session")
	_, err = backend.Sweep(ctx)
	require.ErrorContains(t, err, "postgres session backend: sweep expired sessions")
}

func count(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var rows int
	require.NoError(t, pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&rows))
	return rows
}
