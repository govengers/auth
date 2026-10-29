package redisbackend_test

import (
	"context"
	"fmt"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/govengers/auth/session"
	"github.com/govengers/auth/session/redisbackend"
)

// ExampleNew shares sessions between replicas: every replica builds its Store on a backend pointing at
// the same Redis. The caller owns the client and closes it. miniredis stands in for the server here.
func ExampleNew() {
	server, err := miniredis.Run()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer server.Close()
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer func() { _ = client.Close() }()

	backend, err := redisbackend.New(&redisbackend.Options{Client: client, KeyPrefix: "myapp:session"})
	if err != nil {
		fmt.Println(err)
		return
	}
	key, err := session.ParseKey("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		fmt.Println(err)
		return
	}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("session lifetime:", store.MaximumAge())

	// The backend itself stores opaque values per (session ID, key) and refuses Puts after Revoke.
	ctx := context.Background()
	if err := backend.Put(ctx, "session-id", "key", []byte("value"), time.Hour); err != nil {
		fmt.Println(err)
		return
	}
	value, found, err := backend.Get(ctx, "session-id", "key")
	fmt.Println(string(value), found, err)
	if err := backend.Revoke(ctx, "session-id", time.Hour); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(backend.Put(ctx, "session-id", "key", []byte("value"), time.Hour))

	// Output:
	// session lifetime: 24h0m0s
	// value true <nil>
	// session revoked
}
