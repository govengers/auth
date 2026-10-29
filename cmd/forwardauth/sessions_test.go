package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
)

// fakeRedis accepts connections on a loopback port, counts them and hands each to handle. It stops
// when the test ends.
func fakeRedis(t *testing.T, handle func(connection net.Conn)) (string, *atomic.Int32) {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	accepted := &atomic.Int32{}
	var connections sync.WaitGroup
	connections.Go(func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return // the listener was closed
			}
			accepted.Add(1)
			connections.Go(func() { handle(connection) })
		}
	})
	t.Cleanup(func() {
		_ = listener.Close() // ends the accept loop
		connections.Wait()
	})
	return listener.Addr().String(), accepted
}

func redisConfiguration(address string) *Configuration {
	configuration := validOIDCConfiguration()
	configuration.SessionRedisEnabled, configuration.SessionRedisAddress = true, address
	return configuration
}

func TestTheRedisClientNeverRetriesACommand(t *testing.T) {
	address, accepted := fakeRedis(t, func(connection net.Conn) { _ = connection.Close() }) // every answer is lost
	client := newRedisClient(redisConfiguration(address))
	t.Cleanup(func() { _ = client.Close() }) // nothing to flush

	err := client.Ping(t.Context()).Err()

	require.Error(t, err)
	require.Equal(t, int32(1), accepted.Load(), "one connection, no retry")
}

func TestTheRedisClientHonoursTheContextDeadline(t *testing.T) {
	address, _ := fakeRedis(t, func(connection net.Conn) {
		_, _ = io.Copy(io.Discard, connection) // reads every command, answers none
	})
	client := newRedisClient(redisConfiguration(address))
	t.Cleanup(func() { _ = client.Close() }) // closes the stalled connections, which ends the fake's copies
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()

	err := client.Ping(ctx).Err()

	require.Error(t, err)
	require.Less(t, time.Since(start), 2*time.Second, "the 5 s read timeout of go-redis must not apply")
}

func TestNewSessionsFailsWhenRedisDoesNotAnswer(t *testing.T) {
	address, _ := fakeRedis(t, func(connection net.Conn) { _ = connection.Close() })

	created, err := newSessions(t.Context(), redisConfiguration(address))

	require.ErrorContains(t, err, "SESSION_REDIS_ADDRESS: ping Redis at "+address)
	require.Nil(t, created)
}

func TestNewSessionsUsesRedisAndPingsItForReadiness(t *testing.T) {
	redisServer := miniredis.RunT(t)

	created, err := newSessions(t.Context(), redisConfiguration(redisServer.Addr()))

	require.NoError(t, err)
	require.NoError(t, created.readinessCheck()(t.Context()))
	redisServer.SetError("down")
	require.Error(t, created.readinessCheck()(t.Context()))
	created.close(slog.New(slog.DiscardHandler))
	require.ErrorContains(t, created.closeRedis(), "client is closed", "close released the client")
}
